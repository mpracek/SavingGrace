//! The filtering decision for one DNS packet.

use super::{DnsStats, Transport};
use crate::rules::{Action, RuleEngine, RuleType};
use crate::state::Shared;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RData;
use std::future::Future;
use std::io;
use std::sync::Arc;

/// Firefox asks this name whether it should enable DoH by default. NXDOMAIN
/// tells it to keep using the system resolver. (Extra layer; the registry
/// policy is the primary control.)
pub const FIREFOX_DOH_CANARY: &str = "use-application-dns.net";

/// Where upstream answers come from. A trait so tests can supply canned answers.
pub trait Upstream: Send + Sync + 'static {
    fn query(
        &self,
        packet: &[u8],
        transport: Transport,
    ) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

/// Supplies the current rule engine (swapped atomically when rules change).
pub trait EngineProvider: Send + Sync + 'static {
    fn engine(&self) -> Arc<RuleEngine>;
}

impl EngineProvider for Arc<Shared> {
    fn engine(&self) -> Arc<RuleEngine> {
        Shared::engine(self)
    }
}

impl EngineProvider for Arc<RuleEngine> {
    fn engine(&self) -> Arc<RuleEngine> {
        Arc::clone(self)
    }
}

pub struct DnsFilter<U: Upstream, E: EngineProvider> {
    engine: E,
    upstream: U,
    stats: Arc<DnsStats>,
}

fn response_skeleton(req: &Message, code: ResponseCode) -> Message {
    let mut resp = Message::new();
    resp.set_id(req.id())
        .set_message_type(MessageType::Response)
        .set_op_code(req.op_code())
        .set_recursion_desired(req.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(code);
    for q in req.queries() {
        resp.add_query(q.clone());
    }
    if let Some(e) = req.extensions() {
        let mut edns = Edns::new();
        edns.set_max_payload(e.max_payload().clamp(512, 4096));
        resp.set_edns(edns);
    }
    resp
}

fn encode(msg: &Message) -> Option<Vec<u8>> {
    msg.to_vec().ok()
}

/// Minimal FORMERR for packets we cannot parse but whose id we can read.
fn formerr_from_raw(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    Some(vec![
        packet[0], packet[1], 0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
    ])
}

impl<U: Upstream, E: EngineProvider> DnsFilter<U, E> {
    pub fn new(engine: E, upstream: U, stats: Arc<DnsStats>) -> Self {
        Self {
            engine,
            upstream,
            stats,
        }
    }

    pub fn stats(&self) -> &Arc<DnsStats> {
        &self.stats
    }

    pub fn upstream(&self) -> &U {
        &self.upstream
    }

    /// Handles one query packet. `None` means "send nothing" (not a query we should answer).
    pub async fn handle(&self, packet: &[u8], transport: Transport) -> Option<Vec<u8>> {
        DnsStats::bump(&self.stats.queries);
        let req = match Message::from_vec(packet) {
            Ok(m) => m,
            Err(_) => {
                DnsStats::bump(&self.stats.malformed);
                return formerr_from_raw(packet);
            }
        };
        if req.message_type() != MessageType::Query {
            return None;
        }
        if req.op_code() != OpCode::Query {
            return encode(&response_skeleton(&req, ResponseCode::NotImp));
        }
        if req.queries().len() != 1 {
            DnsStats::bump(&self.stats.malformed);
            return encode(&response_skeleton(&req, ResponseCode::FormErr));
        }
        let name = req.queries()[0].name().to_ascii();
        let engine = self.engine.engine();
        let decision = engine.evaluate_dns_name(&name);

        if name
            .trim_end_matches('.')
            .eq_ignore_ascii_case(FIREFOX_DOH_CANARY)
            || decision.action == Action::Block
        {
            DnsStats::bump(&self.stats.blocked);
            return encode(&response_skeleton(&req, ResponseCode::NXDomain));
        }

        let raw = match self.upstream.query(packet, transport).await {
            Ok(r) => r,
            Err(_) => {
                DnsStats::bump(&self.stats.upstream_errors);
                return encode(&response_skeleton(&req, ResponseCode::ServFail));
            }
        };
        let answer = match Message::from_vec(&raw) {
            Ok(a)
                if a.id() == req.id()
                    && a.message_type() == MessageType::Response
                    && same_question(&req, &a) =>
            {
                a
            }
            _ => {
                DnsStats::bump(&self.stats.upstream_errors);
                return encode(&response_skeleton(&req, ResponseCode::ServFail));
            }
        };

        // CNAME cloaking: an innocent-looking name that aliases a blocked one.
        // An explicit allowlist entry for the queried name is the user's decision and is honoured.
        if decision.rule_type != RuleType::Allowlist && answer_hits_blocklist(&engine, &answer) {
            DnsStats::bump(&self.stats.blocked);
            return encode(&response_skeleton(&req, ResponseCode::NXDomain));
        }
        DnsStats::bump(&self.stats.forwarded);
        Some(raw)
    }
}

fn same_question(req: &Message, ans: &Message) -> bool {
    match (req.queries().first(), ans.queries().first()) {
        (Some(a), Some(b)) => {
            a.query_type() == b.query_type()
                && a.query_class() == b.query_class()
                && a.name()
                    .to_ascii()
                    .eq_ignore_ascii_case(&b.name().to_ascii())
        }
        _ => false,
    }
}

fn answer_hits_blocklist(engine: &RuleEngine, answer: &Message) -> bool {
    answer.answers().iter().any(|rec| {
        let owner_blocked =
            engine.evaluate_dns_name(&rec.name().to_ascii()).action == Action::Block;
        let target_blocked = match rec.data() {
            Some(RData::CNAME(t)) => {
                engine.evaluate_dns_name(&t.0.to_ascii()).action == Action::Block
            }
            _ => false,
        };
        owner_blocked || target_blocked
    })
}
