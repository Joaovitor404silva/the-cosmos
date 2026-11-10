use futures::io::{ReadHalf, WriteHalf};
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{PeerId, Stream, StreamProtocol};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/bb/udp-tunnel/2.0.0");
pub const ACCEPT: u8 = 1;
pub const REJECT: u8 = 0;
const CLOSE: u16 = 0xFFFF;
const QUEUE: usize = 256;
const MAX_UDP_PACKET_SIZE: usize = 8192;
const MAX_PACKETS_PER_SECOND: f64 = 512.0;
const PACKET_BURST: f64 = 1024.0;

#[derive(Default)]
pub struct Targets {
    pub default: Option<SocketAddr>,
    pub peers: HashMap<PeerId, SocketAddr>,
}

impl Targets {
    pub fn get(&self, peer: &PeerId) -> Option<SocketAddr> {
        self.peers.get(peer).copied().or(self.default)
    }
}

pub type SharedTargets = Arc<Mutex<Targets>>;

pub enum Ctl {
    Attach { sid: u64, stream: Stream, rank: u8 },
    Drop { sid: u64 },
    Close,
    Stop,
}

pub enum Note {
    Ended { peer: PeerId, sid: u64 },
    RemoteClosed { peer: PeerId },
}

pub fn bind_loopback() -> io::Result<UdpSocket> {
    let s = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s)
}

pub fn spawn(
    peer: PeerId,
    sock: UdpSocket,
    targets: SharedTargets,
    notes: mpsc::UnboundedSender<Note>,
) -> mpsc::UnboundedSender<Ctl> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(run(peer, Arc::new(sock), targets, rx, notes));
    tx
}

struct Writer {
    sid: u64,
    rank: u8,
    wr: WriteHalf<Stream>,
}

fn best(writers: &[Writer]) -> Option<usize> {
    let top = writers.iter().map(|w| w.rank).max()?;
    writers.iter().rposition(|w| w.rank == top)
}

async fn send(
    writers: &mut Vec<Writer>,
    frame: &[u8],
    peer: PeerId,
    notes: &mpsc::UnboundedSender<Note>,
) -> bool {
    while let Some(i) = best(writers) {
        let w = &mut writers[i];
        let ok = w.wr.write_all(frame).await.is_ok() && w.wr.flush().await.is_ok();
        if ok {
            return true;
        }
        let w = writers.remove(i);
        let _ = notes.send(Note::Ended { peer, sid: w.sid });
    }
    false
}

async fn run(
    peer: PeerId,
    sock: Arc<UdpSocket>,
    targets: SharedTargets,
    mut ctl: mpsc::UnboundedReceiver<Ctl>,
    notes: mpsc::UnboundedSender<Note>,
) {
    let learned: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut writers: Vec<Writer> = Vec::new();
    let mut readers: HashMap<u64, JoinHandle<()>> = HashMap::new();
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut buf = vec![0u8; 2 + MAX_UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf[2..]) => {
                let (n, from) = match r {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(_) => break,
                };
                if n > MAX_UDP_PACKET_SIZE {
                    continue;
                }
                if n >= CLOSE as usize {
                    continue;
                }
                let target = targets.lock().unwrap().get(&peer);
                match target {
                    Some(t) if t != from => continue,
                    Some(_) => {}
                    None => *learned.lock().unwrap() = Some(from),
                }
                buf[..2].copy_from_slice(&(n as u16).to_be_bytes());
                if !send(&mut writers, &buf[..2 + n], peer, &notes).await {
                    if queue.len() >= QUEUE {
                        queue.pop_front();
                    }
                    queue.push_back(buf[..2 + n].to_vec());
                }
            }
            c = ctl.recv() => match c {
                Some(Ctl::Attach { sid, stream, rank }) => {
                    let (rd, wr) = stream.split();
                    let h = tokio::spawn(read_loop(peer, sid, rd, sock.clone(), targets.clone(), learned.clone(), notes.clone()));
                    readers.insert(sid, h);
                    writers.push(Writer { sid, rank, wr });
                    while let Some(f) = queue.pop_front() {
                        if !send(&mut writers, &f, peer, &notes).await {
                            queue.push_front(f);
                            break;
                        }
                    }
                }
                Some(Ctl::Drop { sid }) => {
                    if let Some(i) = writers.iter().position(|w| w.sid == sid) {
                        let mut w = writers.remove(i);
                        let _ = w.wr.close().await;
                    }
                    if let Some(h) = readers.get(&sid) {
                        if h.is_finished() {
                            readers.remove(&sid);
                        }
                    }
                }
                Some(Ctl::Stop) | None => break,
                Some(Ctl::Close) => {
                    for w in writers.iter_mut() {
                        let _ = w.wr.write_all(&CLOSE.to_be_bytes()).await;
                        let _ = w.wr.flush().await;
                        let _ = w.wr.close().await;
                    }
                    break;
                }
            }
        }
    }
    for h in readers.values() {
        h.abort();
    }
}

async fn read_loop(
    peer: PeerId,
    sid: u64,
    mut rd: ReadHalf<Stream>,
    sock: Arc<UdpSocket>,
    targets: SharedTargets,
    learned: Arc<Mutex<Option<SocketAddr>>>,
    notes: mpsc::UnboundedSender<Note>,
) {
    let mut len = [0u8; 2];
    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    let mut packet_tokens = PACKET_BURST;
    let mut packet_updated = Instant::now();
    loop {
        if rd.read_exact(&mut len).await.is_err() {
            break;
        }
        let n = u16::from_be_bytes(len);
        if n == CLOSE {
            let _ = notes.send(Note::RemoteClosed { peer });
            return;
        }
        let n = n as usize;
        if n > MAX_UDP_PACKET_SIZE {
            break;
        }
        if rd.read_exact(&mut buf[..n]).await.is_err() {
            break;
        }
        let now = Instant::now();
        packet_tokens = (packet_tokens
            + now.duration_since(packet_updated).as_secs_f64() * MAX_PACKETS_PER_SECOND)
            .min(PACKET_BURST);
        packet_updated = now;
        if packet_tokens < 1.0 {
            continue;
        }
        packet_tokens -= 1.0;
        let to = targets
            .lock()
            .unwrap()
            .get(&peer)
            .or(*learned.lock().unwrap());
        if let Some(to) = to {
            let _ = sock.send_to(&buf[..n], to).await;
        }
    }
    let _ = notes.send(Note::Ended { peer, sid });
}
