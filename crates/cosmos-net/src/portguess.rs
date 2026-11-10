use libp2p::StreamProtocol;
use sha2::{Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

pub const PROTO: StreamProtocol = StreamProtocol::new("/bb/portguess/1.0.0");
pub const MAX_PPS: u32 = 100;
pub const MAX_SOCKETS: usize = 256;
pub const MAX_SPRAY: Duration = Duration::from_secs(20);
pub const OFFER_LEN: usize = 16 + 4 + 2;
const MAGIC: [u8; 4] = *b"BBPG";
const PROBE: u8 = 1;
const ACK: u8 = 2;
const PACKET_LEN: usize = 4 + 1 + 16;
const ACK_REPEAT: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub sockets: usize,
    pub pps: u32,
    pub spray_for: Duration,
    pub ports: (u16, u16),
    pub local_base: u16,
}

impl Default for Plan {
    fn default() -> Self {
        Plan {
            sockets: MAX_SOCKETS,
            pps: MAX_PPS,
            spray_for: Duration::from_secs(10),
            ports: (1024, 65535),
            local_base: 0,
        }
    }
}

impl Plan {
    pub fn capped(&self) -> Plan {
        let (lo, hi) = self.ports;
        let lo = lo.max(1);
        Plan {
            sockets: self.sockets.clamp(1, MAX_SOCKETS),
            pps: self.pps.clamp(1, MAX_PPS),
            spray_for: self.spray_for.min(MAX_SPRAY),
            ports: (lo, hi.max(lo)),
            local_base: self.local_base,
        }
    }

    fn tick(&self) -> Duration {
        Duration::from_secs(1) / self.pps
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub nonce: [u8; 16],
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl Offer {
    pub fn encode(&self) -> [u8; OFFER_LEN] {
        let mut b = [0u8; OFFER_LEN];
        b[..16].copy_from_slice(&self.nonce);
        b[16..20].copy_from_slice(&self.ip.octets());
        b[20..].copy_from_slice(&self.port.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Offer> {
        if b.len() != OFFER_LEN {
            return None;
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&b[..16]);
        let ip = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
        let port = u16::from_be_bytes([b[20], b[21]]);
        ip_plausible(ip).then_some(Offer { nonce, ip, port })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Win {
    pub local_port: u16,
    pub remote: SocketAddrV4,
}

pub fn ip_plausible(ip: Ipv4Addr) -> bool {
    let [a, _, _, _] = ip.octets();
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() && a != 0 && a < 224
}

pub fn nonce() -> [u8; 16] {
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let seed = kp.to_protobuf_encoding().unwrap_or_default();
    let h = Sha256::digest(&seed);
    let mut n = [0u8; 16];
    n.copy_from_slice(&h[..16]);
    n
}

struct Rng(u64);

impl Rng {
    fn new(seed: &[u8; 16]) -> Rng {
        let mut s = u64::from_le_bytes(seed[..8].try_into().unwrap())
            ^ u64::from_le_bytes(seed[8..].try_into().unwrap());
        if s == 0 {
            s = 0x9e37_79b9_7f4a_7c15;
        }
        Rng(s)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn port(&mut self, (lo, hi): (u16, u16)) -> u16 {
        let span = (hi - lo) as u64 + 1;
        lo + (self.next() % span) as u16
    }
}

fn packet(kind: u8, nonce: &[u8; 16]) -> [u8; PACKET_LEN] {
    let mut b = [0u8; PACKET_LEN];
    b[..4].copy_from_slice(&MAGIC);
    b[4] = kind;
    b[5..].copy_from_slice(nonce);
    b
}

fn parse(b: &[u8], expect: &[u8; 16]) -> Option<u8> {
    if b.len() != PACKET_LEN || b[..4] != MAGIC || &b[5..] != expect {
        return None;
    }
    matches!(b[4], PROBE | ACK).then_some(b[4])
}

fn from_peer(from: SocketAddr, ip: Ipv4Addr) -> Option<SocketAddrV4> {
    match from {
        SocketAddr::V4(v) if *v.ip() == ip => Some(v),
        _ => None,
    }
}

pub fn bind(port: u16) -> io::Result<UdpSocket> {
    let s = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s)
}

fn reader(
    i: usize,
    s: Arc<UdpSocket>,
    tx: mpsc::Sender<(usize, SocketAddr, Vec<u8>)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            match s.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if tx.send((i, from, buf[..n].to_vec())).await.is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(_) => return,
            }
        }
    })
}

async fn finish(s: &UdpSocket, to: SocketAddrV4, nonce: &[u8; 16]) {
    let ack = packet(ACK, nonce);
    for _ in 0..ACK_REPEAT {
        let _ = s.send_to(&ack, to).await;
    }
}

struct Readers(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Readers {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

pub async fn many(plan: &Plan, peer: Offer, mine: [u8; 16]) -> Result<Win, String> {
    let plan = plan.capped();
    if !ip_plausible(peer.ip) || peer.port == 0 {
        return Err("bad peer offer".into());
    }
    let mut socks = Vec::with_capacity(plan.sockets);
    for i in 0..plan.sockets {
        let port = if plan.local_base == 0 {
            0
        } else {
            plan.local_base.saturating_add(i as u16)
        };
        if let Ok(s) = bind(port) {
            socks.push(Arc::new(s));
        }
    }
    if socks.is_empty() {
        return Err("no sockets".into());
    }
    let (tx, mut rx) = mpsc::channel(64);
    let _readers = Readers(
        socks
            .iter()
            .enumerate()
            .map(|(i, s)| reader(i, s.clone(), tx.clone()))
            .collect(),
    );
    drop(tx);
    let target = SocketAddrV4::new(peer.ip, peer.port);
    let probe = packet(PROBE, &peer.nonce);
    let deadline = Instant::now() + plan.spray_for;
    let mut pace = tokio::time::interval(plan.tick());
    pace.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut next = 0usize;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Err("port guess gave up".into()),
            _ = pace.tick() => {
                let s = &socks[next % socks.len()];
                next += 1;
                let _ = s.send_to(&probe, target).await;
            }
            m = rx.recv() => {
                let Some((i, from, b)) = m else { return Err("sockets closed".into()) };
                let Some(from) = from_peer(from, peer.ip) else { continue };
                let s = &socks[i];
                match parse(&b, &mine) {
                    Some(PROBE) => {
                        let _ = s.send_to(&probe, from).await;
                    }
                    Some(_) => {
                        let local_port = s.local_addr().map(|a| a.port()).unwrap_or(0);
                        return Ok(Win { local_port, remote: from });
                    }
                    None => {}
                }
            }
        }
    }
}

pub async fn spray(
    plan: &Plan,
    sock: UdpSocket,
    peer: Offer,
    mine: [u8; 16],
) -> Result<Win, String> {
    let plan = plan.capped();
    if !ip_plausible(peer.ip) {
        return Err("bad peer offer".into());
    }
    let local_port = sock.local_addr().map_err(|e| e.to_string())?.port();
    let sock = Arc::new(sock);
    let (tx, mut rx) = mpsc::channel(64);
    let _readers = Readers(vec![reader(0, sock.clone(), tx)]);
    let probe = packet(PROBE, &peer.nonce);
    let mut rng = Rng::new(&mine);
    let deadline = Instant::now() + plan.spray_for;
    let mut pace = tokio::time::interval(plan.tick());
    pace.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Err("port guess gave up".into()),
            _ = pace.tick() => {
                let to = SocketAddrV4::new(peer.ip, rng.port(plan.ports));
                let _ = sock.send_to(&probe, to).await;
            }
            m = rx.recv() => {
                let Some((_, from, b)) = m else { return Err("socket closed".into()) };
                let Some(from) = from_peer(from, peer.ip) else { continue };
                if parse(&b, &mine) != Some(PROBE) {
                    continue;
                }
                finish(&sock, from, &peer.nonce).await;
                return Ok(Win { local_port, remote: from });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;

    fn free_base(n: u16) -> u16 {
        for _ in 0..50 {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let p = probe.local_addr().unwrap().port();
            drop(probe);
            let base = p.saturating_sub(n).max(20000);
            let ok = (0..n).all(|i| std::net::UdpSocket::bind(("0.0.0.0", base + i)).is_ok());
            if ok {
                return base;
            }
        }
        panic!("no free port range");
    }

    #[test]
    fn offer_roundtrip_and_rejects_bad_ip() {
        let o = Offer {
            nonce: nonce(),
            ip: Ipv4Addr::new(8, 8, 8, 8),
            port: 4242,
        };
        assert_eq!(Offer::decode(&o.encode()), Some(o));
        let mut bad = o.encode();
        bad[16..20].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(Offer::decode(&bad), None);
        bad[16..20].copy_from_slice(&[224, 0, 0, 1]);
        assert_eq!(Offer::decode(&bad), None);
        assert_eq!(Offer::decode(&o.encode()[..10]), None);
        assert_ne!(nonce(), nonce());
    }

    #[test]
    fn plan_caps_rate_sockets_and_duration() {
        let p = Plan {
            sockets: 10_000,
            pps: 50_000,
            spray_for: Duration::from_secs(600),
            ports: (0, 0),
            local_base: 0,
        }
        .capped();
        assert_eq!(p.sockets, MAX_SOCKETS);
        assert_eq!(p.pps, MAX_PPS);
        assert_eq!(p.spray_for, MAX_SPRAY);
        assert_eq!(p.ports, (1, 1));
        assert!(p.tick() >= Duration::from_millis(10));
        let d = Plan::default().capped();
        assert_eq!(d, Plan::default());
    }

    #[test]
    fn packet_auth_needs_exact_nonce() {
        let n = nonce();
        let other = nonce();
        assert_eq!(parse(&packet(PROBE, &n), &n), Some(PROBE));
        assert_eq!(parse(&packet(ACK, &n), &n), Some(ACK));
        assert_eq!(parse(&packet(PROBE, &other), &n), None);
        let mut wrong_magic = packet(PROBE, &n);
        wrong_magic[0] = b'X';
        assert_eq!(parse(&wrong_magic, &n), None);
        let mut wrong_kind = packet(PROBE, &n);
        wrong_kind[4] = 9;
        assert_eq!(parse(&wrong_kind, &n), None);
        assert_eq!(parse(&packet(PROBE, &n)[..PACKET_LEN - 1], &n), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn many_and_spray_meet_on_loopback() {
        let base = free_base(16);
        let plan = Plan {
            sockets: 16,
            pps: 100,
            spray_for: Duration::from_secs(5),
            ports: (base, base + 15),
            local_base: base,
        };
        let (na, nb) = (nonce(), nonce());
        let sb = bind(0).unwrap();
        let pb = sb.local_addr().unwrap().port();
        let a_offer = Offer {
            nonce: na,
            ip: LO,
            port: 0,
        };
        let b_offer = Offer {
            nonce: nb,
            ip: LO,
            port: pb,
        };
        let t0 = Instant::now();
        let (wa, wb) = tokio::join!(many(&plan, b_offer, na), spray(&plan, sb, a_offer, nb));
        let (wa, wb) = (wa.expect("initiator"), wb.expect("responder"));
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "slow: {:?}",
            t0.elapsed()
        );
        assert_eq!(wa.remote.port(), pb);
        assert_eq!(wb.local_port, pb);
        assert_eq!(wb.remote.port(), wa.local_port);
        assert!((base..base + 16).contains(&wa.local_port));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_nonce_never_wins_and_gives_up() {
        let base = free_base(8);
        let plan = Plan {
            sockets: 8,
            pps: 100,
            spray_for: Duration::from_millis(1500),
            ports: (base, base + 7),
            local_base: base,
        };
        let (na, nb, forged) = (nonce(), nonce(), nonce());
        let sb = bind(0).unwrap();
        let pb = sb.local_addr().unwrap().port();
        let t0 = Instant::now();
        let (wa, wb) = tokio::join!(
            many(
                &plan,
                Offer {
                    nonce: forged,
                    ip: LO,
                    port: pb
                },
                na
            ),
            spray(
                &plan,
                sb,
                Offer {
                    nonce: forged,
                    ip: LO,
                    port: 0
                },
                nb
            )
        );
        assert!(wa.unwrap_err().contains("gave up"));
        assert!(wb.unwrap_err().contains("gave up"));
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(1400) && took < Duration::from_secs(3),
            "{took:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spray_rate_is_capped() {
        let sink = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = sink.local_addr().unwrap().port();
        let got = Arc::new(AtomicUsize::new(0));
        let (s2, g2) = (sink.clone(), got.clone());
        let h = tokio::spawn(async move {
            let mut b = [0u8; 64];
            loop {
                if s2.recv_from(&mut b).await.is_ok() {
                    g2.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let plan = Plan {
            sockets: 1,
            pps: 100_000,
            spray_for: Duration::from_secs(1),
            ports: (port, port),
            local_base: 0,
        };
        let r = spray(
            &plan,
            bind(0).unwrap(),
            Offer {
                nonce: nonce(),
                ip: LO,
                port: 0,
            },
            nonce(),
        )
        .await;
        assert!(r.is_err());
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.abort();
        let n = got.load(Ordering::SeqCst);
        assert!(n > 50 && n <= MAX_PPS as usize + 2, "sent {n} probes in 1s");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ignores_packets_from_other_ips() {
        let base = free_base(4);
        let plan = Plan {
            sockets: 4,
            pps: 100,
            spray_for: Duration::from_millis(800),
            ports: (base, base + 3),
            local_base: base,
        };
        let (na, nb) = (nonce(), nonce());
        let sb = bind(0).unwrap();
        let pb = sb.local_addr().unwrap().port();
        let elsewhere = Ipv4Addr::new(192, 0, 2, 1);
        let (wa, _) = tokio::join!(
            many(
                &plan,
                Offer {
                    nonce: nb,
                    ip: elsewhere,
                    port: pb
                },
                na
            ),
            spray(
                &plan,
                sb,
                Offer {
                    nonce: na,
                    ip: LO,
                    port: 0
                },
                nb
            )
        );
        assert!(
            wa.is_err(),
            "initiator accepted a probe from an IP the peer never offered"
        );
    }
}
