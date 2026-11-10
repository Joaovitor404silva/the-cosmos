//! Channel layer: framing and per-lane sequence numbers.
//!
//! Sequence numbers belong to the session, not to the connection: a frame is
//! `[tag][channel][seq u64][payload]` and the receiver orders and dedups by
//! `seq` alone. A path switch (M2) can therefore resend unacknowledged frames
//! over a new transport without loss or duplicates.

use std::collections::{BTreeMap, HashMap};

pub type Channel = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Delivery {
    /// Ordered, no loss, no duplicates.
    Reliable,
    /// Best effort: may be lost; stale or duplicate frames are dropped.
    Unreliable,
}

/// One independent sequence space between two peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Lane {
    Ctrl,
    Data(Channel, Delivery),
}

impl Lane {
    fn ordered(self) -> bool {
        !matches!(self, Lane::Data(_, Delivery::Unreliable))
    }
}

pub(crate) const HEADER: usize = 10;
const TAG_CTRL: u8 = 0;
const TAG_RELIABLE: u8 = 1;
const TAG_UNRELIABLE: u8 = 2;

pub(crate) fn encode(lane: Lane, seq: u64, payload: &[u8]) -> Vec<u8> {
    let (tag, chan) = match lane {
        Lane::Ctrl => (TAG_CTRL, 0),
        Lane::Data(c, Delivery::Reliable) => (TAG_RELIABLE, c),
        Lane::Data(c, Delivery::Unreliable) => (TAG_UNRELIABLE, c),
    };
    let mut f = Vec::with_capacity(HEADER + payload.len());
    f.push(tag);
    f.push(chan);
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

pub(crate) fn decode(b: &[u8]) -> Option<(Lane, u64, &[u8])> {
    if b.len() < HEADER {
        return None;
    }
    let lane = match (b[0], b[1]) {
        (TAG_CTRL, 0) => Lane::Ctrl,
        (TAG_RELIABLE, c) => Lane::Data(c, Delivery::Reliable),
        (TAG_UNRELIABLE, c) => Lane::Data(c, Delivery::Unreliable),
        _ => return None,
    };
    let seq = u64::from_be_bytes(b[2..HEADER].try_into().ok()?);
    Some((lane, seq, &b[HEADER..]))
}

/// Max payload size per channel; larger messages are refused on send and
/// dropped on receive.
#[derive(Clone, Debug)]
pub struct ChannelCaps {
    pub default: usize,
    pub per_channel: HashMap<Channel, usize>,
}

impl Default for ChannelCaps {
    fn default() -> Self {
        Self {
            default: 16 << 10,
            per_channel: HashMap::new(),
        }
    }
}

impl ChannelCaps {
    pub fn with(mut self, channel: Channel, cap: usize) -> Self {
        self.per_channel.insert(channel, cap);
        self
    }

    pub fn cap(&self, channel: Channel) -> usize {
        *self.per_channel.get(&channel).unwrap_or(&self.default)
    }

    /// Largest frame any channel can produce.
    pub fn max_frame(&self) -> usize {
        HEADER + self.per_channel.values().copied().fold(self.default, usize::max).max(CTRL_CAP)
    }
}

pub(crate) const CTRL_CAP: usize = 8 << 10;
/// Ordered lanes hold at most this many frames ahead of the next expected one.
const REORDER_WINDOW: u64 = 1024;
/// Bytes buffered for reordering per peer, across lanes.
const REORDER_BYTES: usize = 1 << 20;

#[derive(Default)]
struct Rx {
    next: u64,
    ahead: BTreeMap<u64, Option<Vec<u8>>>,
}

/// Send and receive sequence state for one peer.
#[derive(Default)]
pub(crate) struct Lanes {
    tx: HashMap<Lane, u64>,
    rx: HashMap<Lane, Rx>,
    buffered: usize,
}

impl Lanes {
    pub(crate) fn next_seq(&mut self, lane: Lane) -> u64 {
        let s = self.tx.entry(lane).or_default();
        *s += 1;
        *s - 1
    }

    /// Feed one received frame. `None` marks a frame that was dropped (e.g.
    /// oversize) but still consumes its sequence number. Returns payloads now
    /// deliverable, in order.
    pub(crate) fn accept(&mut self, lane: Lane, seq: u64, payload: Option<Vec<u8>>) -> Vec<Vec<u8>> {
        let rx = self.rx.entry(lane).or_default();
        if seq < rx.next {
            return vec![];
        }
        if !lane.ordered() {
            rx.next = seq + 1;
            return payload.into_iter().collect();
        }
        if seq >= rx.next + REORDER_WINDOW || rx.ahead.contains_key(&seq) {
            return vec![];
        }
        let size = payload.as_ref().map_or(0, Vec::len);
        if seq != rx.next && self.buffered + size > REORDER_BYTES {
            return vec![];
        }
        self.buffered += size;
        rx.ahead.insert(seq, payload);
        let mut out = vec![];
        while let Some(p) = rx.ahead.remove(&rx.next) {
            rx.next += 1;
            if let Some(p) = p {
                self.buffered -= p.len();
                out.push(p);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REL: Lane = Lane::Data(3, Delivery::Reliable);
    const UNREL: Lane = Lane::Data(3, Delivery::Unreliable);

    fn p(n: u8) -> Option<Vec<u8>> {
        Some(vec![n])
    }

    #[test]
    fn frame_roundtrip_and_garbage() {
        for lane in [Lane::Ctrl, REL, UNREL] {
            let f = encode(lane, 42, b"hey");
            assert_eq!(decode(&f), Some((lane, 42, &b"hey"[..])));
        }
        assert_eq!(decode(&[1, 2, 3]), None);
        let mut f = encode(REL, 1, b"x");
        f[0] = 9;
        assert_eq!(decode(&f), None);
    }

    #[test]
    fn tx_seq_is_per_lane() {
        let mut l = Lanes::default();
        assert_eq!(l.next_seq(REL), 0);
        assert_eq!(l.next_seq(REL), 1);
        assert_eq!(l.next_seq(UNREL), 0);
        assert_eq!(l.next_seq(Lane::Ctrl), 0);
    }

    #[test]
    fn reliable_reorders_and_dedups() {
        let mut l = Lanes::default();
        assert!(l.accept(REL, 2, p(2)).is_empty());
        assert_eq!(l.accept(REL, 0, p(0)), vec![vec![0]]);
        assert_eq!(l.accept(REL, 1, p(1)), vec![vec![1], vec![2]]);
        assert!(l.accept(REL, 1, p(1)).is_empty(), "duplicate delivered");
        assert!(l.accept(REL, 2, p(2)).is_empty(), "duplicate delivered");
        assert_eq!(l.accept(REL, 3, p(3)), vec![vec![3]]);
    }

    #[test]
    fn reliable_window_is_bounded() {
        let mut l = Lanes::default();
        assert!(l.accept(REL, REORDER_WINDOW + 5, p(9)).is_empty());
        assert_eq!(l.buffered, 0, "far-ahead frame buffered");
    }

    #[test]
    fn dropped_frame_still_consumes_its_seq() {
        let mut l = Lanes::default();
        assert!(l.accept(REL, 0, None).is_empty());
        assert_eq!(l.accept(REL, 1, p(1)), vec![vec![1]]);
    }

    #[test]
    fn unreliable_tolerates_loss_drops_stale() {
        let mut l = Lanes::default();
        assert_eq!(l.accept(UNREL, 0, p(0)), vec![vec![0]]);
        assert_eq!(l.accept(UNREL, 5, p(5)), vec![vec![5]], "gap stalled delivery");
        assert!(l.accept(UNREL, 3, p(3)).is_empty(), "stale delivered");
        assert!(l.accept(UNREL, 5, p(5)).is_empty(), "duplicate delivered");
        assert_eq!(l.accept(UNREL, 6, p(6)), vec![vec![6]]);
    }

    #[test]
    fn lanes_are_independent() {
        let mut l = Lanes::default();
        assert!(l.accept(Lane::Data(1, Delivery::Reliable), 1, p(1)).is_empty());
        assert_eq!(l.accept(Lane::Data(2, Delivery::Reliable), 0, p(7)), vec![vec![7]]);
    }

    #[test]
    fn caps_per_channel() {
        let c = ChannelCaps::default().with(5, 100);
        assert_eq!(c.cap(5), 100);
        assert_eq!(c.cap(6), c.default);
    }
}
