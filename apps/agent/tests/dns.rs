//! DNS filter tests: logic with a fake upstream, then real UDP/TCP sockets on loopback.

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use savinggrace_agent::config::InvalidInputPolicy;
use savinggrace_agent::dns::filter::{DnsFilter, Upstream};
use savinggrace_agent::dns::upstream::UdpTcpUpstream;
use savinggrace_agent::dns::{server, DnsStats, Transport};
use savinggrace_agent::domain::DomainRuleEntry;
use savinggrace_agent::rules::RuleEngine;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

fn entry(d: &str, sub: bool) -> DomainRuleEntry {
    DomainRuleEntry {
        domain: d.into(),
        include_subdomains: sub,
        category: Some("adult".into()),
    }
}

fn engine(allow: &[&str], global: &[&str]) -> Arc<RuleEngine> {
    let a: Vec<_> = allow.iter().map(|d| entry(d, true)).collect();
    let g: Vec<_> = global.iter().map(|d| entry(d, true)).collect();
    Arc::new(RuleEngine::new(&a, &[], &g, InvalidInputPolicy::Allow).unwrap())
}

fn query_msg(name: &str, rtype: RecordType, id: u16) -> Message {
    let mut m = Message::new();
    m.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    m.add_query(Query::query(Name::from_str(name).unwrap(), rtype));
    m
}

fn query(name: &str, rtype: RecordType) -> Vec<u8> {
    query_msg(name, rtype, 0x1234).to_vec().unwrap()
}

#[derive(Clone)]
enum Behaviour {
    Answer(Vec<(String, RData)>),
    Fail,
    WrongId,
    WrongQuestion,
}

struct Fake {
    behaviour: Mutex<Behaviour>,
    calls: AtomicUsize,
}

impl Fake {
    fn new(b: Behaviour) -> Self {
        Self {
            behaviour: Mutex::new(b),
            calls: AtomicUsize::new(0),
        }
    }
    fn answering_a(ip: [u8; 4]) -> Self {
        Self::new(Behaviour::Answer(vec![(
            "*".into(),
            RData::A(A(Ipv4Addr::from(ip))),
        )]))
    }
}

impl Upstream for Fake {
    async fn query(&self, packet: &[u8], _t: Transport) -> io::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let req = Message::from_vec(packet).unwrap();
        let b = self.behaviour.lock().unwrap().clone();
        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_recursion_available(true);
        match b {
            Behaviour::Fail => return Err(io::Error::new(io::ErrorKind::TimedOut, "boom")),
            Behaviour::WrongId => {
                resp.set_id(req.id().wrapping_add(1));
                resp.add_query(req.queries()[0].clone());
            }
            Behaviour::WrongQuestion => {
                resp.add_query(Query::query(
                    Name::from_str("other.example.").unwrap(),
                    RecordType::A,
                ));
            }
            Behaviour::Answer(records) => {
                resp.add_query(req.queries()[0].clone());
                for (owner, data) in records {
                    let name = if owner == "*" {
                        req.queries()[0].name().clone()
                    } else {
                        Name::from_str(&owner).unwrap()
                    };
                    resp.add_answer(Record::from_rdata(name, 60, data));
                }
            }
        }
        Ok(resp.to_vec().unwrap())
    }
}

fn filter(e: Arc<RuleEngine>, f: Fake) -> DnsFilter<Fake, Arc<RuleEngine>> {
    DnsFilter::new(e, f, Arc::new(DnsStats::default()))
}

fn rcode(bytes: &[u8]) -> ResponseCode {
    Message::from_vec(bytes).unwrap().response_code()
}

async fn ask(f: &DnsFilter<Fake, Arc<RuleEngine>>, name: &str, t: RecordType) -> Vec<u8> {
    f.handle(&query(name, t), Transport::Udp)
        .await
        .expect("a response")
}

#[tokio::test]
async fn blocked_names_get_nxdomain_without_touching_upstream() {
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::answering_a([1, 2, 3, 4]),
    );
    for name in [
        "bad.example.",
        "www.bad.example.",
        "A.B.BAD.Example.",
        "x-1.bad.EXAMPLE.",
    ] {
        for t in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::TXT,
            RecordType::ANY,
        ] {
            let r = ask(&f, name, t).await;
            assert_eq!(rcode(&r), ResponseCode::NXDomain, "{name} {t}");
            let m = Message::from_vec(&r).unwrap();
            assert_eq!(m.id(), 0x1234);
            assert_eq!(m.message_type(), MessageType::Response);
            assert!(m.answers().is_empty());
            assert_eq!(m.queries().len(), 1);
        }
    }
    assert_eq!(f.upstream().calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.stats().snapshot().blocked, 20);
}

#[tokio::test]
async fn allowed_names_are_forwarded_byte_for_byte() {
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::answering_a([93, 184, 216, 34]),
    );
    let r = ask(&f, "good.example.", RecordType::A).await;
    let m = Message::from_vec(&r).unwrap();
    assert_eq!(m.response_code(), ResponseCode::NoError);
    assert_eq!(m.answers().len(), 1);
    assert_eq!(f.upstream().calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.stats().snapshot().forwarded, 1);
}

#[tokio::test]
async fn lookalike_names_are_not_blocked() {
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::answering_a([1, 1, 1, 1]),
    );
    for name in [
        "bad.example.evil.com.",
        "evil-bad.example.",
        "notbad.example.",
        "example.",
    ] {
        assert_eq!(
            rcode(&ask(&f, name, RecordType::A).await),
            ResponseCode::NoError,
            "{name}"
        );
    }
}

#[tokio::test]
async fn allowlist_beats_global_blocklist() {
    let f = filter(
        engine(&["ok.bad.example"], &["bad.example"]),
        Fake::answering_a([1, 1, 1, 1]),
    );
    assert_eq!(
        rcode(&ask(&f, "ok.bad.example.", RecordType::A).await),
        ResponseCode::NoError
    );
    assert_eq!(
        rcode(&ask(&f, "other.bad.example.", RecordType::A).await),
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn cname_cloaking_to_a_blocked_domain_is_blocked() {
    let chain = vec![
        (
            "*".to_string(),
            RData::CNAME(CNAME(Name::from_str("tracker.bad.example.").unwrap())),
        ),
        (
            "tracker.bad.example.".to_string(),
            RData::A(A(Ipv4Addr::new(6, 6, 6, 6))),
        ),
    ];
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::new(Behaviour::Answer(chain.clone())),
    );
    assert_eq!(
        rcode(&ask(&f, "innocent.example.", RecordType::A).await),
        ResponseCode::NXDomain
    );
    assert_eq!(f.upstream().calls.load(Ordering::SeqCst), 1);

    // The user explicitly allowed the queried name: honour that decision.
    let f2 = filter(
        engine(&["innocent.example"], &["bad.example"]),
        Fake::new(Behaviour::Answer(chain)),
    );
    assert_eq!(
        rcode(&ask(&f2, "innocent.example.", RecordType::A).await),
        ResponseCode::NoError
    );
}

#[tokio::test]
async fn answer_records_owned_by_a_blocked_name_are_blocked() {
    let recs = vec![(
        "deep.bad.example.".to_string(),
        RData::A(A(Ipv4Addr::new(6, 6, 6, 6))),
    )];
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::new(Behaviour::Answer(recs)),
    );
    assert_eq!(
        rcode(&ask(&f, "innocent.example.", RecordType::A).await),
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn firefox_doh_canary_is_always_nxdomain() {
    let f = filter(engine(&[], &[]), Fake::answering_a([1, 1, 1, 1]));
    assert_eq!(
        rcode(&ask(&f, "use-application-dns.net.", RecordType::A).await),
        ResponseCode::NXDomain
    );
    assert_eq!(
        rcode(&ask(&f, "USE-APPLICATION-DNS.NET.", RecordType::AAAA).await),
        ResponseCode::NXDomain
    );
    assert_eq!(f.upstream().calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn names_with_odd_label_bytes_cannot_hide_a_blocked_suffix() {
    // A URL parser would read `x\\` + `.bad.example` as host "x"; the DNS path must not.
    // The upstream answer is owned by an innocent name so only the first-layer decision can block it.
    let neutral = vec![(
        "fine.example.".to_string(),
        RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
    )];
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::new(Behaviour::Answer(neutral)),
    );
    let mut name = Name::new();
    for label in [&b"x\\"[..], b"bad", b"example"] {
        name = name.append_label(label).unwrap();
    }
    let mut m = Message::new();
    m.set_id(7)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true);
    m.add_query(Query::query(name, RecordType::A));
    let r = f
        .handle(&m.to_vec().unwrap(), Transport::Udp)
        .await
        .unwrap();
    assert_eq!(rcode(&r), ResponseCode::NXDomain);
}

#[tokio::test]
async fn malformed_and_unusual_packets_are_handled_safely() {
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::answering_a([1, 1, 1, 1]),
    );
    assert!(f.handle(&[], Transport::Udp).await.is_none());
    assert!(f.handle(&[1, 2, 3], Transport::Udp).await.is_none());
    // 12+ bytes of garbage: FORMERR echoing the id.
    let garbage = [
        0xAB, 0xCD, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 9, 9, 9,
    ];
    let r = f.handle(&garbage, Transport::Udp).await.unwrap();
    assert_eq!(&r[..2], &[0xAB, 0xCD]);
    assert_eq!(rcode(&r), ResponseCode::FormErr);
    // A response packet is never answered.
    let mut resp = query_msg("a.example.", RecordType::A, 1);
    resp.set_message_type(MessageType::Response);
    assert!(f
        .handle(&resp.to_vec().unwrap(), Transport::Udp)
        .await
        .is_none());
    // Two questions.
    let mut two = query_msg("a.example.", RecordType::A, 2);
    two.add_query(Query::query(
        Name::from_str("b.example.").unwrap(),
        RecordType::A,
    ));
    assert_eq!(
        rcode(
            &f.handle(&two.to_vec().unwrap(), Transport::Udp)
                .await
                .unwrap()
        ),
        ResponseCode::FormErr
    );
    // Non-query opcode.
    let mut status = query_msg("a.example.", RecordType::A, 3);
    status.set_op_code(OpCode::Status);
    assert_eq!(
        rcode(
            &f.handle(&status.to_vec().unwrap(), Transport::Udp)
                .await
                .unwrap()
        ),
        ResponseCode::NotImp
    );
    assert_eq!(f.upstream().calls.load(Ordering::SeqCst), 0);
    assert!(f.stats().snapshot().malformed >= 2);
}

#[tokio::test]
async fn upstream_failures_and_spoofed_answers_become_servfail() {
    for b in [
        Behaviour::Fail,
        Behaviour::WrongId,
        Behaviour::WrongQuestion,
    ] {
        let f = filter(engine(&[], &[]), Fake::new(b));
        assert_eq!(
            rcode(&ask(&f, "good.example.", RecordType::A).await),
            ResponseCode::ServFail
        );
        assert_eq!(f.stats().snapshot().upstream_errors, 1);
    }
}

#[tokio::test]
async fn edns_is_preserved_in_generated_answers() {
    let f = filter(
        engine(&[], &["bad.example"]),
        Fake::answering_a([1, 1, 1, 1]),
    );
    let mut q = query_msg("bad.example.", RecordType::A, 5);
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    q.set_edns(edns);
    let r = Message::from_vec(
        &f.handle(&q.to_vec().unwrap(), Transport::Udp)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r.extensions().as_ref().map(|e| e.max_payload()), Some(1232));
}

// ---- real sockets -----------------------------------------------------------------

async fn start_server(
    e: Arc<RuleEngine>,
    up: Fake,
) -> (server::DnsServerHandle, SocketAddr, watch::Sender<bool>) {
    let f = Arc::new(filter(e, up));
    let (tx, rx) = watch::channel(false);
    let h = server::start(&["127.0.0.1:0".parse().unwrap()], f, rx).await;
    assert!(h.failed.is_empty(), "{:?}", h.failed);
    let addr = h.bound[0];
    (h, addr, tx)
}

async fn udp_ask(addr: SocketAddr, name: &str, id: u16) -> Message {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(&query_msg(name, RecordType::A, id).to_vec().unwrap(), addr)
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), s.recv_from(&mut buf))
        .await
        .expect("no udp reply")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

async fn tcp_ask(s: &mut TcpStream, name: &str, id: u16) -> Message {
    let q = query_msg(name, RecordType::A, id).to_vec().unwrap();
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend(q);
    s.write_all(&framed).await.unwrap();
    let mut lb = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut lb))
        .await
        .expect("no tcp reply")
        .unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(lb) as usize];
    s.read_exact(&mut body).await.unwrap();
    Message::from_vec(&body).unwrap()
}

#[tokio::test]
async fn server_answers_over_udp_and_tcp_and_shuts_down() {
    let (h, addr, tx) = start_server(
        engine(&[], &["bad.example"]),
        Fake::answering_a([9, 9, 9, 9]),
    )
    .await;
    assert_eq!(
        udp_ask(addr, "www.bad.example.", 11).await.response_code(),
        ResponseCode::NXDomain
    );
    let ok = udp_ask(addr, "good.example.", 12).await;
    assert_eq!(
        (ok.id(), ok.response_code(), ok.answers().len()),
        (12, ResponseCode::NoError, 1)
    );

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        tcp_ask(&mut tcp, "bad.example.", 21).await.response_code(),
        ResponseCode::NXDomain
    );
    // Same connection, second query (pipelining of sequential queries).
    assert_eq!(
        tcp_ask(&mut tcp, "good.example.", 22).await.answers().len(),
        1
    );

    tx.send(true).unwrap();
    h.join().await;
    assert!(
        UdpSocket::bind(addr).await.is_ok(),
        "port must be free after shutdown"
    );
}

#[tokio::test]
async fn server_handles_many_concurrent_queries() {
    let (_h, addr, _tx) = start_server(
        engine(&[], &["bad.example"]),
        Fake::answering_a([9, 9, 9, 9]),
    )
    .await;
    let mut tasks = Vec::new();
    for i in 0..100u16 {
        tasks.push(tokio::spawn(async move {
            let (name, expect) = if i % 2 == 0 {
                ("x.bad.example.", ResponseCode::NXDomain)
            } else {
                ("fine.example.", ResponseCode::NoError)
            };
            let m = udp_ask(addr, name, i).await;
            assert_eq!((m.id(), m.response_code()), (i, expect));
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test]
async fn tcp_garbage_and_oversize_frames_do_not_break_the_server() {
    let (_h, addr, _tx) = start_server(engine(&[], &[]), Fake::answering_a([9, 9, 9, 9])).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&[0, 0]).await.unwrap(); // zero-length frame closes the connection
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut sink)).await;
    let mut s2 = TcpStream::connect(addr).await.unwrap();
    s2.write_all(&[0xFF, 0xFF, 1, 2, 3]).await.unwrap(); // claims 65535 bytes, sends 3, then drops
    drop(s2);
    assert_eq!(
        udp_ask(addr, "good.example.", 99).await.response_code(),
        ResponseCode::NoError
    );
}

#[tokio::test]
async fn bind_failure_is_reported_not_fatal() {
    let blocker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let busy = blocker.local_addr().unwrap();
    let f = Arc::new(filter(engine(&[], &[]), Fake::answering_a([1, 1, 1, 1])));
    let (_tx, rx) = watch::channel(false);
    let h = server::start(&[busy, "127.0.0.1:0".parse().unwrap()], f, rx).await;
    assert_eq!(h.failed.len(), 1);
    assert_eq!(h.bound.len(), 1);
}

// ---- real upstream forwarder -------------------------------------------------------

async fn fake_udp_dns(truncate: bool) -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = s.recv_from(&mut buf).await else {
                return;
            };
            let req = Message::from_vec(&buf[..n]).unwrap();
            let mut r = Message::new();
            r.set_id(req.id())
                .set_message_type(MessageType::Response)
                .set_truncated(truncate);
            r.add_query(req.queries()[0].clone());
            if !truncate {
                r.add_answer(Record::from_rdata(
                    req.queries()[0].name().clone(),
                    30,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
                ));
            }
            let _ = s.send_to(&r.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

async fn fake_tcp_dns(addr: SocketAddr) {
    let l = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut lb = [0u8; 2];
                c.read_exact(&mut lb).await.unwrap();
                let mut b = vec![0u8; u16::from_be_bytes(lb) as usize];
                c.read_exact(&mut b).await.unwrap();
                let req = Message::from_vec(&b).unwrap();
                let mut r = Message::new();
                r.set_id(req.id()).set_message_type(MessageType::Response);
                r.add_query(req.queries()[0].clone());
                r.add_answer(Record::from_rdata(
                    req.queries()[0].name().clone(),
                    30,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, 2))),
                ));
                let out = r.to_vec().unwrap();
                let mut f = (out.len() as u16).to_be_bytes().to_vec();
                f.extend(out);
                c.write_all(&f).await.unwrap();
            });
        }
    });
}

#[tokio::test]
async fn forwarder_uses_udp_then_tcp_on_truncation_and_fails_over() {
    let q = query("a.example.", RecordType::A);
    // plain UDP answer
    let ok = fake_udp_dns(false).await;
    let up = UdpTcpUpstream::new(vec![ok], Duration::from_secs(1));
    let r = Message::from_vec(&up.query(&q, Transport::Udp).await.unwrap()).unwrap();
    assert_eq!(r.answers().len(), 1);

    // truncated UDP -> TCP on the same address
    let trunc = fake_udp_dns(true).await;
    fake_tcp_dns(trunc).await;
    let up = UdpTcpUpstream::new(vec![trunc], Duration::from_secs(1));
    let r = Message::from_vec(&up.query(&q, Transport::Udp).await.unwrap()).unwrap();
    assert!(
        matches!(r.answers()[0].data(), Some(RData::A(A(ip))) if *ip == Ipv4Addr::new(10, 0, 0, 2))
    );

    // first server is dead -> second answers
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // bound but silent
    let up = UdpTcpUpstream::new(
        vec![dead.local_addr().unwrap(), ok],
        Duration::from_millis(200),
    );
    assert!(up.query(&q, Transport::Udp).await.is_ok());

    // nothing known / nothing answering
    let none = UdpTcpUpstream::new(vec![], Duration::from_millis(100));
    assert!(none.query(&q, Transport::Udp).await.is_err());
    let silent = UdpTcpUpstream::new(vec![dead.local_addr().unwrap()], Duration::from_millis(150));
    assert!(silent.query(&q, Transport::Udp).await.is_err());

    // empty replacement is ignored, a real one replaces
    up.set_servers(vec![]);
    assert_eq!(up.servers().len(), 2);
    up.set_servers(vec![ok]);
    assert_eq!(up.servers(), vec![ok]);
}

#[tokio::test]
async fn end_to_end_blocklist_through_real_forwarder() {
    let upstream_addr = fake_udp_dns(false).await;
    let up = UdpTcpUpstream::new(vec![upstream_addr], Duration::from_secs(1));
    let f = Arc::new(DnsFilter::new(
        engine(&[], &["bad.example"]),
        up,
        Arc::new(DnsStats::default()),
    ));
    let (_tx, rx) = watch::channel(false);
    let h = server::start(&["127.0.0.1:0".parse().unwrap()], f, rx).await;
    let addr = h.bound[0];
    assert_eq!(
        udp_ask(addr, "shop.bad.example.", 1).await.response_code(),
        ResponseCode::NXDomain
    );
    let ok = udp_ask(addr, "fine.example.", 2).await;
    assert!(
        matches!(ok.answers()[0].data(), Some(RData::A(A(ip))) if *ip == Ipv4Addr::new(10, 0, 0, 1))
    );
}
