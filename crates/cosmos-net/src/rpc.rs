use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::Instant;

pub const PROTO: StreamProtocol = StreamProtocol::new("/bb/rpc/1.0.0");
const CHUNK: usize = 8 << 10;
const PEER_TABLE_MAX: usize = 4096;

#[derive(Clone, Debug)]
pub struct RpcLimits {
    pub max_request: usize,
    pub max_reply: usize,
    pub max_in_flight: usize,
    pub max_in_flight_per_peer: usize,
    pub max_in_flight_per_ip: usize,
    pub reserved_trusted: usize,
    pub per_peer_per_sec: u32,
    pub burst: u32,
    pub read_timeout: Duration,
    pub handler_timeout: Duration,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            max_request: 64 << 10,
            max_reply: 1 << 20,
            max_in_flight: 64,
            max_in_flight_per_peer: 8,
            max_in_flight_per_ip: 16,
            reserved_trusted: 16,
            per_peer_per_sec: 20,
            burst: 40,
            read_timeout: Duration::from_secs(5),
            handler_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RpcStats {
    pub in_flight: usize,
    pub peak_in_flight: usize,
    pub peak_in_flight_per_peer: usize,
    pub accepted: u64,
    pub served: u64,
    pub rejected_busy: u64,
    pub rejected_rate: u64,
    pub too_large: u64,
    pub timed_out: u64,
    pub buffered: usize,
    pub peak_buffered: usize,
}

pub struct RpcRequest {
    pub peer: PeerId,
    pub data: Vec<u8>,
    pub reply: oneshot::Sender<Vec<u8>>,
}

struct PeerState {
    in_flight: usize,
    tokens: f64,
    last: Instant,
}

#[derive(Default)]
struct Counters {
    peak_in_flight: AtomicUsize,
    peak_per_peer: AtomicUsize,
    accepted: AtomicU64,
    served: AtomicU64,
    rejected_busy: AtomicU64,
    rejected_rate: AtomicU64,
    too_large: AtomicU64,
    timed_out: AtomicU64,
    buffered: AtomicUsize,
    peak_buffered: AtomicUsize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Bucket {
    Ip(IpAddr),
    Relay(PeerId),
    Unknown,
}

pub struct Gate {
    limits: RpcLimits,
    sem: Arc<Semaphore>,
    peers: Mutex<HashMap<PeerId, PeerState>>,
    ips: Mutex<HashMap<Bucket, usize>>,
    c: Counters,
}

pub struct Permit {
    gate: Arc<Gate>,
    peer: PeerId,
    ip: Option<Bucket>,
    _global: OwnedSemaphorePermit,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(p) = self.gate.peers.lock().unwrap().get_mut(&self.peer) {
            p.in_flight = p.in_flight.saturating_sub(1);
        }
        if let Some(ip) = self.ip {
            let mut ips = self.gate.ips.lock().unwrap();
            if let Some(n) = ips.get_mut(&ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    ips.remove(&ip);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Rate,
    Busy,
}

struct Buffered<'a>(&'a Counters, usize);

impl Buffered<'_> {
    fn add(&mut self, n: usize) {
        self.1 += n;
        let now = self.0.buffered.fetch_add(n, Ordering::Relaxed) + n;
        self.0.peak_buffered.fetch_max(now, Ordering::Relaxed);
    }
}

impl Drop for Buffered<'_> {
    fn drop(&mut self) {
        self.0.buffered.fetch_sub(self.1, Ordering::Relaxed);
    }
}

impl Gate {
    pub fn new(limits: RpcLimits) -> Arc<Self> {
        let sem = Arc::new(Semaphore::new(limits.max_in_flight.max(1)));
        Arc::new(Gate {
            limits,
            sem,
            peers: Mutex::new(HashMap::new()),
            ips: Mutex::new(HashMap::new()),
            c: Counters::default(),
        })
    }

    pub fn limits(&self) -> &RpcLimits {
        &self.limits
    }

    #[cfg(test)]
    fn admit(self: &Arc<Self>, peer: PeerId) -> Result<Permit, Reject> {
        self.admit_from(peer, None, true)
    }

    #[cfg(test)]
    pub fn admit_from(
        self: &Arc<Self>,
        peer: PeerId,
        ip: Option<IpAddr>,
        trusted: bool,
    ) -> Result<Permit, Reject> {
        self.admit_bucket(peer, ip.map(Bucket::Ip).unwrap_or(Bucket::Unknown), trusted)
    }

    pub fn admit_bucket(
        self: &Arc<Self>,
        peer: PeerId,
        bucket: Bucket,
        trusted: bool,
    ) -> Result<Permit, Reject> {
        let now = Instant::now();
        let l = &self.limits;
        let mut peers = self.peers.lock().unwrap();
        if peers.len() >= PEER_TABLE_MAX && !peers.contains_key(&peer) {
            peers.retain(|_, p| {
                p.in_flight > 0 || now.duration_since(p.last) < Duration::from_secs(60)
            });
            if peers.len() >= PEER_TABLE_MAX {
                let idle = peers
                    .iter()
                    .filter(|(_, p)| p.in_flight == 0)
                    .min_by_key(|(_, p)| p.last)
                    .map(|(k, _)| *k);
                match idle {
                    Some(k) => {
                        peers.remove(&k);
                    }
                    None if trusted => {}
                    None => {
                        self.c.rejected_busy.fetch_add(1, Ordering::Relaxed);
                        return Err(Reject::Busy);
                    }
                }
            }
        }
        let burst = l.burst.max(1) as f64;
        let st = peers.entry(peer).or_insert(PeerState {
            in_flight: 0,
            tokens: burst,
            last: now,
        });
        let dt = now.duration_since(st.last).as_secs_f64();
        st.tokens = (st.tokens + dt * l.per_peer_per_sec as f64).min(burst);
        st.last = now;
        if st.tokens < 1.0 {
            self.c.rejected_rate.fetch_add(1, Ordering::Relaxed);
            return Err(Reject::Rate);
        }
        st.tokens -= 1.0;
        if st.in_flight >= l.max_in_flight_per_peer {
            self.c.rejected_busy.fetch_add(1, Ordering::Relaxed);
            return Err(Reject::Busy);
        }
        let reserved = if trusted {
            0
        } else {
            l.reserved_trusted.min(l.max_in_flight.max(1) / 2)
        };
        if self.sem.available_permits() <= reserved {
            self.c.rejected_busy.fetch_add(1, Ordering::Relaxed);
            return Err(Reject::Busy);
        }
        let ip = if trusted { None } else { Some(bucket) };
        let mut ips = self.ips.lock().unwrap();
        if let Some(ip) = ip {
            if ips.get(&ip).copied().unwrap_or(0) >= l.max_in_flight_per_ip.max(1) {
                self.c.rejected_busy.fetch_add(1, Ordering::Relaxed);
                return Err(Reject::Busy);
            }
        }
        let Ok(global) = self.sem.clone().try_acquire_owned() else {
            self.c.rejected_busy.fetch_add(1, Ordering::Relaxed);
            return Err(Reject::Busy);
        };
        if let Some(ip) = ip {
            *ips.entry(ip).or_insert(0) += 1;
        }
        drop(ips);
        st.in_flight += 1;
        self.c
            .peak_per_peer
            .fetch_max(st.in_flight, Ordering::Relaxed);
        let used = l.max_in_flight.max(1) - self.sem.available_permits();
        self.c.peak_in_flight.fetch_max(used, Ordering::Relaxed);
        self.c.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(Permit {
            gate: self.clone(),
            peer,
            ip,
            _global: global,
        })
    }

    pub fn stats(&self) -> RpcStats {
        let c = &self.c;
        RpcStats {
            in_flight: self.limits.max_in_flight.max(1) - self.sem.available_permits(),
            peak_in_flight: c.peak_in_flight.load(Ordering::Relaxed),
            peak_in_flight_per_peer: c.peak_per_peer.load(Ordering::Relaxed),
            accepted: c.accepted.load(Ordering::Relaxed),
            served: c.served.load(Ordering::Relaxed),
            rejected_busy: c.rejected_busy.load(Ordering::Relaxed),
            rejected_rate: c.rejected_rate.load(Ordering::Relaxed),
            too_large: c.too_large.load(Ordering::Relaxed),
            timed_out: c.timed_out.load(Ordering::Relaxed),
            buffered: c.buffered.load(Ordering::Relaxed),
            peak_buffered: c.peak_buffered.load(Ordering::Relaxed),
        }
    }
}

pub async fn write_frame<S: futures::AsyncWrite + Unpin>(
    s: &mut S,
    data: &[u8],
) -> anyhow::Result<()> {
    s.write_all(&(data.len() as u32).to_be_bytes()).await?;
    s.write_all(data).await?;
    s.flush().await?;
    Ok(())
}

#[derive(Debug)]
pub struct TooLarge;

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rpc frame too large")
    }
}

impl std::error::Error for TooLarge {}

async fn read_counted<S: futures::AsyncRead + Unpin>(
    s: &mut S,
    max: usize,
    mut count: Option<&mut Buffered<'_>>,
) -> anyhow::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        return Err(TooLarge.into());
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; CHUNK];
    while buf.len() < n {
        let want = (n - buf.len()).min(CHUNK);
        let k = s.read(&mut chunk[..want]).await?;
        if k == 0 {
            return Err(anyhow::anyhow!("rpc stream ended mid-frame"));
        }
        if let Some(c) = count.as_mut() {
            c.add(k);
        }
        buf.extend_from_slice(&chunk[..k]);
    }
    Ok(buf)
}

pub async fn read_frame<S: futures::AsyncRead + Unpin>(
    s: &mut S,
    max: usize,
) -> anyhow::Result<Vec<u8>> {
    read_counted(s, max, None).await
}

pub async fn serve(
    permit: Permit,
    mut stream: libp2p::Stream,
    tx: mpsc::UnboundedSender<RpcRequest>,
) {
    let gate = permit.gate.clone();
    let l = gate.limits.clone();
    let peer = permit.peer;
    let read = {
        let mut count = Buffered(&gate.c, 0);
        tokio::time::timeout(
            l.read_timeout,
            read_counted(&mut stream, l.max_request, Some(&mut count)),
        )
        .await
    };
    let data = match read {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            if e.is::<TooLarge>() {
                gate.c.too_large.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        Err(_) => {
            gate.c.timed_out.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let (reply, rx) = oneshot::channel();
    if tx.send(RpcRequest { peer, data, reply }).is_err() {
        return;
    }
    let Ok(Ok(out)) = tokio::time::timeout(l.handler_timeout, rx).await else {
        gate.c.timed_out.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let sent = tokio::time::timeout(l.read_timeout, async {
        write_frame(&mut stream, &out).await?;
        stream.close().await?;
        anyhow::Ok(())
    })
    .await;
    match sent {
        Ok(Ok(())) => {
            gate.c.served.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Err(_)) => {}
        Err(_) => {
            gate.c.timed_out.fetch_add(1, Ordering::Relaxed);
        }
    }
    drop(permit);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn header_over_cap_is_rejected_without_allocating() {
        let mut src: &[u8] = &u32::MAX.to_be_bytes();
        let e = read_frame(&mut src, 64 << 10).await.unwrap_err();
        assert!(e.is::<TooLarge>());
    }

    #[tokio::test]
    async fn frame_is_read_incrementally() {
        let mut data = (100_000u32).to_be_bytes().to_vec();
        data.extend((0..100_000u32).map(|i| i as u8));
        let mut src: &[u8] = &data;
        let got = read_frame(&mut src, 1 << 20).await.unwrap();
        assert_eq!(got.len(), 100_000);
        let mut short: &[u8] = &data[..1000];
        assert!(read_frame(&mut short, 1 << 20).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn gate_caps_per_peer_global_and_rate() {
        let g = Gate::new(RpcLimits {
            max_in_flight: 3,
            max_in_flight_per_peer: 2,
            burst: 4,
            per_peer_per_sec: 1,
            ..Default::default()
        });
        let (a, b) = (PeerId::random(), PeerId::random());
        let p1 = g.admit(a).unwrap();
        let _p2 = g.admit(a).unwrap();
        assert_eq!(g.admit(a).err(), Some(Reject::Busy));
        let _p3 = g.admit(b).unwrap();
        assert_eq!(g.admit(b).err(), Some(Reject::Busy));
        drop(p1);
        let p4 = g.admit(a).unwrap();
        assert_eq!(g.admit(a).err(), Some(Reject::Rate));
        drop(p4);
        tokio::time::advance(Duration::from_secs(2)).await;
        let _p5 = g.admit(a).unwrap();
        let s = g.stats();
        assert_eq!(
            (s.in_flight, s.peak_in_flight, s.peak_in_flight_per_peer),
            (3, 3, 2)
        );
    }

    #[test]
    fn full_peer_table_evicts_oldest_idle_instead_of_rejecting() {
        let g = Gate::new(RpcLimits {
            burst: 100,
            ..Default::default()
        });
        let first = PeerId::random();
        drop(g.admit_from(first, None, false).unwrap());
        std::thread::sleep(Duration::from_millis(5));
        for _ in 1..PEER_TABLE_MAX {
            drop(g.admit_from(PeerId::random(), None, false).unwrap());
        }
        assert_eq!(g.peers.lock().unwrap().len(), PEER_TABLE_MAX);
        assert!(g.admit_from(PeerId::random(), None, true).is_ok());
        assert!(g.admit_from(PeerId::random(), None, false).is_ok());
        assert!(!g.peers.lock().unwrap().contains_key(&first));
        assert_eq!(g.peers.lock().unwrap().len(), PEER_TABLE_MAX);
    }

    #[test]
    fn untrusted_peers_leave_reserved_slots_and_respect_ip_cap() {
        let g = Gate::new(RpcLimits {
            max_in_flight: 8,
            reserved_trusted: 4,
            max_in_flight_per_ip: 3,
            max_in_flight_per_peer: 8,
            burst: 100,
            ..Default::default()
        });
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut held = vec![];
        for _ in 0..3 {
            held.push(g.admit_from(PeerId::random(), Some(ip), false).unwrap());
        }
        assert_eq!(
            g.admit_from(PeerId::random(), Some(ip), false).err(),
            Some(Reject::Busy)
        );
        held.push(
            g.admit_from(PeerId::random(), Some("10.0.0.2".parse().unwrap()), false)
                .unwrap(),
        );
        assert_eq!(
            g.admit_from(PeerId::random(), Some("10.0.0.3".parse().unwrap()), false)
                .err(),
            Some(Reject::Busy)
        );
        for _ in 0..4 {
            held.push(g.admit_from(PeerId::random(), Some(ip), true).unwrap());
        }
        assert_eq!(
            g.admit_from(PeerId::random(), None, true).err(),
            Some(Reject::Busy)
        );
        held.truncate(1);
        held.push(g.admit_from(PeerId::random(), Some(ip), false).unwrap());
    }

    #[test]
    fn relay_identity_caps_many_remote_peers_and_releases_slots() {
        let gate = Gate::new(RpcLimits {
            max_in_flight_per_ip: 2,
            ..Default::default()
        });
        let relay = Bucket::Relay(PeerId::random());
        let first = gate.admit_bucket(PeerId::random(), relay, false).unwrap();
        let _second = gate.admit_bucket(PeerId::random(), relay, false).unwrap();
        assert_eq!(
            gate.admit_bucket(PeerId::random(), relay, false).err(),
            Some(Reject::Busy)
        );
        assert!(
            gate.admit_bucket(PeerId::random(), Bucket::Relay(PeerId::random()), false)
                .is_ok()
        );
        drop(first);
        assert!(gate.admit_bucket(PeerId::random(), relay, false).is_ok());
    }
}
