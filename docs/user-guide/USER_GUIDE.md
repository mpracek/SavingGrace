# User guide
SavingGrace is not ready for end users yet: there is no installer (Phase 8) and no Admin UI (Phase 6, Slovenian and English). What exists is the agent, which developers and administrators can run. See `docs/user-guide/ADMIN_GUIDE.md`.

What the protection does when fully in place: every program on the computer asks the SavingGrace resolver for website addresses; sites on the block lists get "does not exist" and cannot be opened in any browser. Other ways of looking up addresses are closed. Known gaps (direct IP addresses, VPN/proxy tools, someone with administrator rights) are listed honestly in `docs/threat-model/THREAT_MODEL.md`.
