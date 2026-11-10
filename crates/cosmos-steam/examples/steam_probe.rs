//! Live check of the Steam relay path (needs the Steam client logged in).
//!
//!   steam_probe [--appid N] [--dll PATH] info
//!   steam_probe [--appid N] [--dll PATH] listen [--secs S]
//!   steam_probe [--appid N] [--dll PATH] ping <steamid> [--count N]
//!
//! `listen` prints its SteamID and echoes pings; `ping` handshakes with that
//! SteamID (signed binding), then times reliable and unreliable round trips.
//! Two PCs need two different Steam accounts.

use cosmos_core::{Transport, TransportEvent};
use cosmos_net::Keypair;
use cosmos_steam::{COSMOS_CHANNEL, SteamApi, SteamConfig, SteamTransport, SteamTransportConfig, StaticDirectory};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn usage() -> ! {
    eprintln!("usage: steam_probe [--appid N] [--dll PATH] (info | listen [--secs S] | ping <steamid> [--count N])");
    std::process::exit(2)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut opt = |name: &str| -> Option<String> {
        let i = args.iter().position(|a| a == name)?;
        let v = args.get(i + 1).cloned().unwrap_or_else(|| usage());
        args.drain(i..=i + 1);
        Some(v)
    };
    let app_id = opt("--appid").map(|v| v.parse().unwrap_or_else(|_| usage())).unwrap_or(480);
    let dll = opt("--dll").map(|p| std::path::absolute(PathBuf::from(p)).unwrap_or_else(|_| usage())).or_else(|| {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor/steam").join(cosmos_steam::DLL_NAME);
        (std::env::var_os(cosmos_steam::DLL_ENV).is_none() && dev.exists()).then_some(dev)
    });
    let secs: Option<u64> = opt("--secs").map(|v| v.parse().unwrap_or_else(|_| usage()));
    let count: u32 = opt("--count").map(|v| v.parse().unwrap_or_else(|_| usage())).unwrap_or(20);

    let t0 = Instant::now();
    let api = match SteamApi::load(&SteamConfig { app_id, dll }) {
        Ok(a) => a,
        Err(e) => {
            println!("steam: unavailable ({e})");
            std::process::exit(1);
        }
    };
    println!(
        "steam: ok in {:?}  steam_id={}  app_id={}  borrowed={}",
        t0.elapsed(),
        api.steam_id(),
        api.app_id(),
        api.is_borrowed()
    );
    // The transport's pump runs Steam callbacks, which the relay needs.
    let key = Keypair::generate_ed25519();
    let cfg = SteamTransportConfig { handshake_timeout: Duration::from_secs(30), ..Default::default() };
    let t = SteamTransport::new(api.channel(COSMOS_CHANNEL), key.clone(), Arc::new(StaticDirectory::default()), cfg);
    println!("cosmos peer: {}", key.public().to_peer_id());
    let mut rx = t.take_events().unwrap();

    let t1 = Instant::now();
    let mut relay = api.relay_status();
    while relay != 100 && t1.elapsed() < Duration::from_secs(20) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        relay = api.relay_status();
    }
    println!("relay network: status={relay} ({}) after {:?}", if relay == 100 { "current" } else { "not ready" }, t1.elapsed());

    match args.first().map(String::as_str) {
        Some("info") => {}
        Some("listen") => {
            println!("listening; run on the other PC: steam_probe ping {}", api.steam_id());
            let end = secs.map(|s| Instant::now() + Duration::from_secs(s));
            loop {
                let wait = end.map_or(Duration::from_secs(3600), |e| e.saturating_duration_since(Instant::now()));
                let Ok(Some(ev)) = tokio::time::timeout(wait, rx.recv()).await else { break };
                match ev {
                    TransportEvent::Frame { peer, data } if !data.is_empty() => {
                        let reliable = data[0] == b'R';
                        let _ = t.send(peer, data, reliable);
                    }
                    TransportEvent::Down { peer } => println!("path down: {peer}"),
                    _ => {}
                }
            }
        }
        Some("ping") => {
            let target: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| usage());
            let th = Instant::now();
            let peer = match t.connect_steam(target, None).await {
                Ok(p) => p,
                Err(e) => {
                    println!("handshake failed: {e:#}");
                    drop(t);
                    api.shutdown();
                    std::process::exit(1);
                }
            };
            println!("bound steam {target} <-> cosmos {peer} in {:?}", th.elapsed());
            for (label, reliable) in [("reliable", true), ("unreliable", false)] {
                let mut rtts = vec![];
                for seq in 0..count {
                    let mut f = vec![if reliable { b'R' } else { b'U' }];
                    f.extend_from_slice(&seq.to_be_bytes());
                    let sent = Instant::now();
                    t.send(peer, f, reliable).map_err(|e| anyhow::anyhow!("send: {e}"))?;
                    let deadline = sent + Duration::from_secs(2);
                    loop {
                        let left = deadline.saturating_duration_since(Instant::now());
                        match tokio::time::timeout(left, rx.recv()).await {
                            Ok(Some(TransportEvent::Frame { data, .. })) if data.get(1..5) == Some(&seq.to_be_bytes()[..]) => {
                                rtts.push(sent.elapsed());
                                break;
                            }
                            Ok(Some(_)) => continue,
                            _ => break,
                        }
                    }
                }
                rtts.sort();
                let ms = |d: Duration| d.as_secs_f64() * 1000.0;
                if rtts.is_empty() {
                    println!("{label}: 0/{count} answered");
                } else {
                    println!(
                        "{label}: {}/{count} answered  rtt min {:.1} ms  median {:.1} ms  max {:.1} ms",
                        rtts.len(),
                        ms(rtts[0]),
                        ms(rtts[rtts.len() / 2]),
                        ms(*rtts.last().unwrap())
                    );
                }
            }
        }
        _ => usage(),
    }
    drop(t);
    api.shutdown();
    eprintln!("probe: done");
    Ok(())
}
