use libp2p::PeerId;
use libp2p::identity::{Keypair, PublicKey};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DOMAIN: &[u8] = b"cosmos-record:v1";
pub const MAX_TTL: Duration = Duration::from_secs(1800);
pub const CLOCK_SKEW: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub topic: String,
    pub data: Vec<u8>,
    pub publisher: PeerId,
    pub expires: u64,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn field(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        self.take(len)
    }
}

impl Record {
    pub fn sign(keypair: &Keypair, topic: &str, data: Vec<u8>, ttl: Duration) -> anyhow::Result<Vec<u8>> {
        Self::sign_expiring(keypair, topic, data, now_secs() + ttl.min(MAX_TTL).as_secs())
    }

    fn sign_expiring(keypair: &Keypair, topic: &str, data: Vec<u8>, expires: u64) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        put(&mut buf, &keypair.public().encode_protobuf());
        put(&mut buf, topic.as_bytes());
        put(&mut buf, &data);
        buf.extend_from_slice(&expires.to_be_bytes());
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&buf);
        let sig = keypair.sign(&msg)?;
        put(&mut buf, &sig);
        Ok(buf)
    }

    pub fn verify(bytes: &[u8]) -> Option<Record> {
        Self::verify_at(bytes, now_secs())
    }

    fn verify_at(bytes: &[u8], now: u64) -> Option<Record> {
        let mut r = Reader(bytes);
        let key = PublicKey::try_decode_protobuf(r.field()?).ok()?;
        let topic = String::from_utf8(r.field()?.to_vec()).ok()?;
        let data = r.field()?.to_vec();
        let expires = u64::from_be_bytes(r.take(8)?.try_into().ok()?);
        let signed_len = bytes.len() - r.0.len();
        let sig = r.field()?;
        let skew = CLOCK_SKEW.as_secs();
        if !r.0.is_empty() || expires.saturating_add(skew) <= now || expires > now + MAX_TTL.as_secs() + skew {
            return None;
        }
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&bytes[..signed_len]);
        if !key.verify(&msg, sig) {
            return None;
        }
        Some(Record {
            topic,
            data,
            publisher: key.to_peer_id(),
            expires,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_tamper() {
        let k = Keypair::generate_ed25519();
        let mut bytes = Record::sign(&k, "game:kind", b"hi".to_vec(), Duration::from_secs(60)).unwrap();
        let rec = Record::verify(&bytes).unwrap();
        assert_eq!(rec.publisher, k.public().to_peer_id());
        assert_eq!(rec.data, b"hi");
        let n = bytes.len();
        bytes[n - 70] ^= 1;
        assert!(Record::verify(&bytes).is_none());
    }

    #[test]
    fn expiry_clamped_with_clock_skew() {
        let k = Keypair::generate_ed25519();
        let now = now_secs();
        let at = |e: u64| Record::sign_expiring(&k, "game:kind", vec![1], e).unwrap();
        assert!(Record::verify_at(&at(now + 10 * 365 * 86400), now).is_none(), "far future accepted");
        assert!(Record::verify_at(&at(now + MAX_TTL.as_secs() + 300), now).is_none());
        assert!(Record::verify_at(&at(now + MAX_TTL.as_secs() + 60), now).is_some(), "skew ahead rejected");
        assert!(Record::verify_at(&at(now - 60), now).is_some(), "skew behind rejected");
        assert!(Record::verify_at(&at(now - 300), now).is_none(), "stale accepted");
        assert!(Record::verify_at(&at(u64::MAX), now).is_none());
        let long = Record::sign(&k, "game:kind", vec![1], Duration::from_secs(100 * 86400)).unwrap();
        assert!(Record::verify(&long).is_some(), "signer did not clamp ttl");
    }
}
