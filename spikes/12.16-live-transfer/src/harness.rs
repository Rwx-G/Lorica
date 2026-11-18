//! The traffic and the verdict: TCP and UDP backends and clients in one
//! process, generation 0 of the proxy as a child, then the cross-check of
//! what both ends saw against what every generation logged.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::chan::{field, field_u64};
use crate::util::{arg, parse_args, pct, set_linger_zero, ByteStream, Fnv, Verifier};

const MAGIC: u32 = 0x3132_3136;
const MODE_UNTIL_EOF: u8 = 0;
const MODE_FIXED: u8 = 1;
const TAIL: u64 = 64 * 1024;

#[derive(Default, Clone)]
struct R {
    kind: &'static str,
    port: u16,
    abort: bool,
    c_sent: u64,
    c_sent_hash: u64,
    c_recv: u64,
    c_recv_hash: u64,
    c_mismatch: Option<u64>,
    c_err: Option<String>,
    c_done: bool,
    max_gap_ms: f64,
    b_recv: u64,
    b_recv_hash: u64,
    b_mismatch: Option<u64>,
    b_sent: u64,
    b_sent_hash: u64,
    b_done: bool,
    b_err: Option<String>,
}

type Results = Arc<Mutex<HashMap<u32, R>>>;

#[derive(Clone)]
struct Cfg {
    proxy: SocketAddr,
    backend_tcp: SocketAddr,
    backend_udp: SocketAddr,
    rate: u64,
    stall_rate: u64,
}

fn seed_c2b(idx: u32) -> u64 {
    u64::from(idx) * 2 + 1
}
fn seed_b2c(idx: u32) -> u64 {
    u64::from(idx) * 2 + 2
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

/// Write `total` bytes of `gen` (or until `stop` when paced), returning
/// what was sent and its hash.
async fn send_stream<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    gen: &mut ByteStream,
    total: Option<u64>,
    paced: Option<(u64, Arc<AtomicBool>, Option<Instant>)>,
) -> std::io::Result<(u64, Fnv)> {
    let mut sent = 0u64;
    let mut hash = Fnv::new();
    let mut buf = vec![0u8; 16 * 1024];
    match paced {
        None => {
            let total = total.unwrap_or(0);
            while sent < total {
                let n = ((total - sent) as usize).min(buf.len());
                gen.fill(&mut buf[..n]);
                w.write_all(&buf[..n]).await?;
                hash.update(&buf[..n]);
                sent += n as u64;
            }
        }
        Some((rate, stop, deadline)) => {
            let tick = Duration::from_millis(4);
            let per_tick = (rate * 4 / 1000).max(1) as usize;
            let mut iv = tokio::time::interval(tick);
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            buf.resize(per_tick, 0);
            loop {
                iv.tick().await;
                if stop.load(SeqCst) || deadline.is_some_and(|d| Instant::now() >= d) {
                    break;
                }
                gen.fill(&mut buf);
                w.write_all(&buf).await?;
                hash.update(&buf);
                sent += buf.len() as u64;
            }
        }
    }
    Ok((sent, hash))
}

#[allow(clippy::too_many_arguments)] // a spike's one call site
async fn tcp_client(
    cfg: Cfg,
    res: Results,
    idx: u32,
    kind: &'static str,
    s1: Option<u64>,
    mode: u8,
    s2: u32,
    abort_after_ms: Option<u64>,
    stall: bool,
    deadline: Instant,
) {
    let sock = TcpSocket::new_v4().unwrap();
    if stall {
        let _ = sock.set_recv_buffer_size(4096);
    }
    let s = match sock.connect(cfg.proxy).await {
        Ok(s) => s,
        Err(e) => {
            res.lock().unwrap().entry(idx).or_default().c_err = Some(format!("connect: {e}"));
            return;
        }
    };
    let port = s.local_addr().map(|a| a.port()).unwrap_or(0);
    {
        let mut g = res.lock().unwrap();
        let r = g.entry(idx).or_default();
        r.kind = kind;
        r.port = port;
        r.abort = abort_after_ms.is_some();
    }
    let mut header = [0u8; 16];
    header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    header[4..8].copy_from_slice(&idx.to_le_bytes());
    header[8] = mode;
    header[12..16].copy_from_slice(&s2.to_le_bytes());

    if let Some(ms) = abort_after_ms {
        let mut s = s;
        let mut gen = ByteStream::new(seed_c2b(idx));
        let _ = s.write_all(&header).await;
        let end = Instant::now() + Duration::from_millis(ms);
        let mut buf = vec![0u8; 8192];
        while Instant::now() < end {
            gen.fill(&mut buf);
            if s.write_all(&buf).await.is_err() {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(1), s.read(&mut buf)).await;
        }
        set_linger_zero(std::os::fd::AsRawFd::as_raw_fd(&s));
        drop(s);
        let mut g = res.lock().unwrap();
        g.entry(idx).or_default().c_done = true;
        return;
    }

    let (mut rd, mut wr) = s.into_split();
    let writer = async move {
        wr.write_all(&header).await?;
        let mut gen = ByteStream::new(seed_c2b(idx));
        let out = match s1 {
            Some(n) => send_stream(&mut wr, &mut gen, Some(n), None).await?,
            None => {
                send_stream(
                    &mut wr,
                    &mut gen,
                    None,
                    Some((cfg.rate, Arc::new(AtomicBool::new(false)), Some(deadline))),
                )
                .await?
            }
        };
        wr.shutdown().await?;
        Ok::<_, std::io::Error>((out, wr))
    };
    let reader = async move {
        let mut v = Verifier::new(seed_b2c(idx));
        let mut buf = vec![0u8; 32 * 1024];
        let mut last = Instant::now();
        let mut max_gap = 0f64;
        let mut first = true;
        let mut next_stall = Instant::now() + Duration::from_millis(1500);
        loop {
            if stall && Instant::now() >= next_stall {
                tokio::time::sleep(Duration::from_millis(2500)).await;
                next_stall = Instant::now() + Duration::from_millis(1500);
                last = Instant::now();
            }
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let now = Instant::now();
            if !first {
                max_gap = max_gap.max((now - last).as_secs_f64() * 1000.0);
            }
            first = false;
            last = now;
            v.check(&buf[..n]);
        }
        Ok::<_, std::io::Error>((v, max_gap))
    };
    let (w, r) = tokio::join!(writer, reader);
    let mut g = res.lock().unwrap();
    let e = g.entry(idx).or_default();
    match w {
        Ok(((sent, hash), _wr)) => {
            e.c_sent = sent;
            e.c_sent_hash = hash.0;
        }
        Err(err) => e.c_err = Some(format!("write: {err}")),
    }
    match r {
        Ok((v, gap)) => {
            e.c_recv = v.offset;
            e.c_recv_hash = v.hash.0;
            e.c_mismatch = v.first_mismatch;
            e.max_gap_ms = gap;
        }
        Err(err) => e.c_err = Some(format!("read: {err}")),
    }
    e.c_done = true;
}

async fn tcp_backend_conn(cfg: Cfg, res: Results, mut s: TcpStream) {
    let mut header = [0u8; 16];
    if s.read_exact(&mut header).await.is_err() {
        return;
    }
    let idx = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let mode = header[8];
    let s2 = u32::from_le_bytes(header[12..16].try_into().unwrap());
    let stall = res
        .lock()
        .unwrap()
        .get(&idx)
        .is_some_and(|r| r.kind == "stall");
    let (mut rd, mut wr) = s.into_split();
    let eof = Arc::new(AtomicBool::new(false));
    let eof2 = eof.clone();
    let reader = async move {
        let mut v = Verifier::new(seed_c2b(idx));
        let mut buf = vec![0u8; 32 * 1024];
        let r = loop {
            match rd.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => v.check(&buf[..n]),
                Err(e) => break Err(e),
            }
        };
        eof2.store(true, SeqCst);
        (v, r)
    };
    let rate = if stall { cfg.stall_rate } else { cfg.rate };
    let writer = async move {
        let mut gen = ByteStream::new(seed_b2c(idx));
        let (mut sent, mut hash) = if mode == MODE_FIXED {
            send_stream(&mut wr, &mut gen, Some(u64::from(s2)), None).await?
        } else {
            send_stream(&mut wr, &mut gen, None, Some((rate, eof, None))).await?
        };
        if mode == MODE_UNTIL_EOF {
            let (n, h) = send_stream(&mut wr, &mut gen, Some(TAIL), None).await?;
            // Fold the tail into the hash by re-generating: simpler to
            // hash in one pass, so recompute over the whole stream.
            let _ = h;
            sent += n;
            let mut regen = ByteStream::new(seed_b2c(idx));
            let mut all = Fnv::new();
            let mut left = sent;
            let mut chunk = vec![0u8; 64 * 1024];
            while left > 0 {
                let k = (left as usize).min(chunk.len());
                regen.fill(&mut chunk[..k]);
                all.update(&chunk[..k]);
                left -= k as u64;
            }
            hash = all;
        }
        wr.shutdown().await?;
        Ok::<_, std::io::Error>((sent, hash))
    };
    let ((v, rr), w) = tokio::join!(reader, writer);
    let mut g = res.lock().unwrap();
    let e = g.entry(idx).or_default();
    e.b_recv = v.offset;
    e.b_recv_hash = v.hash.0;
    e.b_mismatch = v.first_mismatch;
    if let Err(err) = rr {
        e.b_err = Some(format!("read: {err}"));
    }
    match w {
        Ok((sent, hash)) => {
            e.b_sent = sent;
            e.b_sent_hash = hash.0;
        }
        Err(err) => e.b_err = Some(format!("write: {err}")),
    }
    e.b_done = true;
}

type Ports = Arc<Mutex<HashMap<u32, HashSet<u16>>>>;

async fn udp_backend(sock: UdpSocket, ports: Ports) {
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if n < 12 {
            continue;
        }
        let id = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        ports
            .lock()
            .unwrap()
            .entry(id)
            .or_default()
            .insert(from.port());
        let _ = sock.send_to(&buf[..64.min(n.max(12))], from).await;
    }
}

struct UdpOut {
    sent: u64,
    uniq: u64,
    dup: u64,
}

async fn udp_client(cfg: Cfg, id: u32, deadline: Instant) -> UdpOut {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    s.connect(cfg.proxy).await.unwrap();
    let s2 = s.clone();
    let sender = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut iv = tokio::time::interval(Duration::from_millis(2));
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&id.to_le_bytes());
        while Instant::now() < deadline {
            iv.tick().await;
            buf[4..12].copy_from_slice(&seq.to_le_bytes());
            if s2.send(&buf).await.is_ok() {
                seq += 1;
            }
        }
        seq
    });
    let mut seen: Vec<bool> = Vec::new();
    let mut dup = 0u64;
    let mut buf = [0u8; 2048];
    let until = deadline + Duration::from_millis(1500);
    while let Ok(Ok(n)) = tokio::time::timeout_at(until, s.recv(&mut buf)).await {
        if n < 12 {
            continue;
        }
        let seq = u64::from_le_bytes(buf[4..12].try_into().unwrap()) as usize;
        if seen.len() <= seq {
            seen.resize(seq + 1, false);
        }
        if seen[seq] {
            dup += 1;
        }
        seen[seq] = true;
    }
    let sent = sender.await.unwrap();
    UdpOut {
        sent,
        uniq: seen.iter().filter(|b| **b).count() as u64,
        dup,
    }
}

fn read_logs(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("log-") {
                if let Ok(text) = std::fs::read_to_string(e.path()) {
                    for l in text.lines() {
                        out.push((name.clone(), l.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// `<mono_ns> <KIND> fields...`
fn kind_of(line: &str) -> (&str, &str) {
    let mut it = line.splitn(3, ' ');
    let _ns = it.next();
    (it.next().unwrap_or(""), it.next().unwrap_or(""))
}

pub fn main(args: &[String]) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let ok = rt.block_on(run(args));
    std::process::exit(if ok { 0 } else { 1 });
}

async fn run(args: &[String]) -> bool {
    let m = parse_args(args);
    let dir = PathBuf::from(arg(&m, "dir", "/tmp/s1216".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let upgrades: u64 = arg(&m, "upgrades", 0);
    let interval_ms: u64 = arg(&m, "interval-ms", 200);
    let n_long: u32 = arg(&m, "long", 4);
    let n_churn: u32 = arg(&m, "churn", 8);
    let n_udp: u32 = arg(&m, "udp", 4);
    let n_stall: u32 = arg(&m, "stall", 0);
    let expect_total_ms: u64 = arg(&m, "total-timeout-ms", 0);
    let duration_ms: u64 = arg(&m, "duration-ms", upgrades * (interval_ms + 30) + 1500);
    let cfg = Cfg {
        proxy: arg(&m, "listen", "127.0.0.1:9000".parse().unwrap()),
        backend_tcp: arg(&m, "backend-tcp", "127.0.0.1:9001".parse().unwrap()),
        backend_udp: arg(&m, "backend-udp", "127.0.0.1:9002".parse().unwrap()),
        rate: arg(&m, "rate", 1_000_000),
        stall_rate: arg(&m, "stall-rate", 4_000_000),
    };
    let label = arg(&m, "label", "run".to_string());

    let res: Results = Arc::new(Mutex::new(HashMap::new()));
    let ports: Ports = Arc::new(Mutex::new(HashMap::new()));
    // The scale scenario's thousand connections arrive at once; the
    // default backlog drops some of them before any upgrade.
    let tl = {
        let sock = TcpSocket::new_v4().unwrap();
        sock.set_reuseaddr(true).unwrap();
        sock.bind(cfg.backend_tcp).unwrap();
        sock.listen(4096).unwrap()
    };
    {
        let (cfg, res) = (cfg.clone(), res.clone());
        tokio::spawn(async move {
            loop {
                if let Ok((s, _)) = tl.accept().await {
                    tokio::spawn(tcp_backend_conn(cfg.clone(), res.clone(), s));
                }
            }
        });
    }
    let us = UdpSocket::bind(cfg.backend_udp).await.unwrap();
    tokio::spawn(udp_backend(us, ports.clone()));

    let mut gen0 = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("proxy")
        .args(args)
        .args(["--gen", "0", "--attempt", "0"])
        .spawn()
        .expect("spawn gen 0");
    for _ in 0..100 {
        if TcpStream::connect(cfg.proxy).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let start = Instant::now();
    let deadline = start + Duration::from_millis(duration_ms);

    let mut tasks = Vec::new();
    let mut idx = 0u32;
    for _ in 0..n_long {
        idx += 1;
        if idx.is_multiple_of(50) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tasks.push(tokio::spawn(tcp_client(
            cfg.clone(),
            res.clone(),
            idx,
            "long",
            None,
            MODE_UNTIL_EOF,
            0,
            None,
            false,
            deadline,
        )));
    }
    for _ in 0..n_stall {
        idx += 1;
        res.lock().unwrap().entry(idx).or_default().kind = "stall";
        tasks.push(tokio::spawn(tcp_client(
            cfg.clone(),
            res.clone(),
            idx,
            "stall",
            None,
            MODE_UNTIL_EOF,
            0,
            None,
            true,
            deadline,
        )));
    }
    let churn_base = Arc::new(Mutex::new(100_000u32));
    for w in 0..n_churn {
        let (cfg, res, base) = (cfg.clone(), res.clone(), churn_base.clone());
        tasks.push(tokio::spawn(async move {
            let mut rng = Rng(0x9E37_79B9 ^ ((u64::from(w) + 1) * 0x1234_5678_9ABC_DEF1));
            while Instant::now() < deadline {
                let i = {
                    let mut b = base.lock().unwrap();
                    *b += 1;
                    *b
                };
                let s1 = rng.below(256 * 1024);
                let s2 = rng.below(256 * 1024) as u32;
                let abort = (rng.below(10) == 0).then(|| rng.below(60));
                tcp_client(
                    cfg.clone(),
                    res.clone(),
                    i,
                    "churn",
                    Some(s1),
                    MODE_FIXED,
                    s2,
                    abort,
                    false,
                    deadline + Duration::from_secs(60),
                )
                .await;
            }
        }));
    }
    let mut udp_tasks = Vec::new();
    for id in 0..n_udp {
        udp_tasks.push(tokio::spawn(udp_client(cfg.clone(), id, deadline)));
    }

    let mut udp_out = Vec::new();
    for t in udp_tasks {
        udp_out.push(t.await.unwrap());
    }
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(90), t).await;
    }
    // Let backends record their side.
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write(dir.join("stop"), "").unwrap();
    for _ in 0..600 {
        if dir.join("final.done").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = gen0.try_wait();
    // Older generations still draining get a moment to log their exit.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let elapsed = start.elapsed().as_secs_f64();

    report(
        &label,
        &dir,
        &res,
        &ports,
        &udp_out,
        expect_total_ms,
        elapsed,
        upgrades,
    )
}

#[allow(clippy::too_many_arguments)] // a spike's one call site
fn report(
    label: &str,
    dir: &Path,
    res: &Results,
    ports: &Ports,
    udp_out: &[UdpOut],
    expect_total_ms: u64,
    elapsed: f64,
    upgrades: u64,
) -> bool {
    let res = res.lock().unwrap().clone();
    let logs = read_logs(dir);
    let mut pass = true;
    println!("== {label} ({elapsed:.1} s)");

    // 1. Bytes, both directions, both ends.
    let mut checked = 0;
    let mut bad = Vec::new();
    let mut aborts = 0;
    let mut bytes_total = 0u64;
    for (idx, r) in &res {
        if r.abort {
            aborts += 1;
            continue;
        }
        checked += 1;
        bytes_total += r.c_sent + r.b_sent;
        let prefix_ok = r.c_mismatch.is_none() && r.b_mismatch.is_none() && r.c_done && r.b_done;
        let ok = if expect_total_ms > 0 {
            prefix_ok
        } else {
            prefix_ok
                && r.c_err.is_none()
                && r.b_err.is_none()
                && r.c_sent == r.b_recv
                && r.c_sent_hash == r.b_recv_hash
                && r.b_sent == r.c_recv
                && r.b_sent_hash == r.c_recv_hash
        };
        if !ok {
            bad.push(format!(
                "idx={idx} kind={} port={} c_sent={} b_recv={} b_sent={} c_recv={} c_mis={:?} b_mis={:?} c_err={:?} b_err={:?} c_done={} b_done={}",
                r.kind, r.port, r.c_sent, r.b_recv, r.b_sent, r.c_recv, r.c_mismatch, r.b_mismatch, r.c_err, r.b_err, r.c_done, r.b_done
            ));
        }
    }
    println!(
        "tcp_connections: {checked} verified, {aborts} aborted on purpose (RST), {} failed, {:.1} MB checked",
        bad.len(),
        bytes_total as f64 / 1e6
    );
    for b in bad.iter().take(10) {
        println!("  FAIL {b}");
    }
    if !bad.is_empty() {
        pass = false;
    }
    let mut gaps: Vec<f64> = res
        .values()
        .filter(|r| r.kind == "long")
        .map(|r| r.max_gap_ms)
        .collect();
    gaps.sort_by(f64::total_cmp);
    if !gaps.is_empty() {
        println!(
            "long_conn_max_read_gap_ms: max {:.1} (per-connection maxima, p50 {:.1})",
            gaps[gaps.len() - 1],
            pct(&gaps, 0.5)
        );
    }

    // 2. Access-log ownership: exactly one END row per connection, with
    // cumulative counters equal to what both ends counted.
    let mut by_port: HashMap<u16, Vec<String>> = HashMap::new();
    let mut reasons: HashMap<String, u32> = HashMap::new();
    let mut max_hops = 0u64;
    let mut hops_sum = 0u64;
    let mut ends = 0u64;
    for (_, l) in &logs {
        let (k, rest) = kind_of(l);
        if k == "END" {
            ends += 1;
            let port: u16 = field(rest, "peer")
                .and_then(|p| p.parse::<SocketAddr>().ok())
                .map(|a| a.port())
                .unwrap_or(0);
            by_port.entry(port).or_default().push(rest.to_string());
            *reasons
                .entry(field(rest, "reason").unwrap_or("?").to_string())
                .or_default() += 1;
            max_hops = max_hops.max(field_u64(rest, "hops"));
            hops_sum += field_u64(rest, "hops");
        }
    }
    let mut harness_ports: HashMap<u16, u32> = HashMap::new();
    for r in res.values() {
        *harness_ports.entry(r.port).or_default() += 1;
    }
    let (mut missing, mut dup_rows, mut wrong_counts, mut missing_abort) = (0, 0, 0, 0);
    for r in res.values() {
        if harness_ports.get(&r.port) != Some(&1) {
            continue;
        }
        let rows = by_port.get(&r.port).map(Vec::len).unwrap_or(0);
        match rows {
            // A client that resets right after connecting can be dropped
            // from the accept queue by the kernel before any accept: no
            // generation ever sees it (the baseline scenario shows it
            // without any upgrade).
            0 if r.abort => missing_abort += 1,
            0 => {
                missing += 1;
                println!(
                    "  MISSING kind={} port={} abort={} c_done={} c_err={:?} c_sent={} c_recv={}",
                    r.kind, r.port, r.abort, r.c_done, r.c_err, r.c_sent, r.c_recv
                );
            }
            1 => {
                if !r.abort && expect_total_ms == 0 {
                    let row = &by_port[&r.port][0];
                    if field_u64(row, "up") != r.c_sent + 16 || field_u64(row, "down") != r.c_recv {
                        wrong_counts += 1;
                        if wrong_counts <= 5 {
                            println!(
                                "  COUNT {row} (client sent {} + 16, received {})",
                                r.c_sent, r.c_recv
                            );
                        }
                    }
                }
            }
            _ => dup_rows += 1,
        }
    }
    let mut reasons: Vec<_> = reasons.into_iter().collect();
    reasons.sort();
    println!(
        "end_rows: {ends} total, missing {missing}, duplicated {dup_rows}, counters wrong {wrong_counts}; reasons {reasons:?}; hops max {max_hops}, sum {hops_sum}"
    );
    println!("aborted_clients_never_accepted: {missing_abort}");
    if missing + dup_rows + wrong_counts > 0 {
        pass = false;
    }
    if expect_total_ms > 0 {
        let mut ok = 0;
        let mut bad_t = 0;
        for rows in by_port.values() {
            for row in rows {
                if field(row, "reason") == Some("total_timeout") {
                    let d = field_u64(row, "dur_ms");
                    if d >= expect_total_ms && d <= expect_total_ms + 1100 {
                        ok += 1;
                    } else {
                        bad_t += 1;
                        println!("  TOTAL {row}");
                    }
                }
            }
        }
        println!("total_timeout_rows: {ok} within [T, T+1.1 s], {bad_t} outside");
        if ok == 0 || bad_t > 0 {
            pass = false;
        }
    }

    // 3. Handovers.
    let mut adopt_ns: HashMap<u64, u64> = HashMap::new();
    let mut presumed = 0;
    for (_, l) in &logs {
        let (k, rest) = kind_of(l);
        if k == "ADOPT" {
            let ns: u64 = l.split(' ').next().unwrap().parse().unwrap();
            adopt_ns.insert(field_u64(rest, "gen"), ns);
            if field(rest, "presumed") == Some("true") {
                presumed += 1;
            }
        }
    }
    let mut outcomes: HashMap<String, u32> = HashMap::new();
    let (mut pause, mut park, mut xfer) = (Vec::new(), Vec::new(), Vec::new());
    let (mut n_tcp, mut n_udp, mut n_fallback, mut n_inel, mut inq, mut outq) =
        (0u64, 0u64, 0u64, 0u64, 0i64, 0i64);
    let (mut held_conns, mut held_bytes) = (0u64, 0u64);
    for (_, l) in &logs {
        let (k, rest) = kind_of(l);
        if k != "HANDOVER" {
            continue;
        }
        let outcome = field(rest, "outcome").unwrap_or("?");
        let key = match field(rest, "reason") {
            Some(r) => format!("{outcome}:{r}"),
            None => outcome.to_string(),
        };
        *outcomes.entry(key).or_default() += 1;
        let pr = field_u64(rest, "park_req");
        park.push((field_u64(rest, "park_done").saturating_sub(pr)) as f64 / 1e6);
        if outcome == "committed" {
            let g = field_u64(rest, "gen");
            if let Some(a) = adopt_ns.get(&(g + 1)) {
                pause.push(a.saturating_sub(pr) as f64 / 1e6);
            }
            xfer.push(
                field_u64(rest, "committed").saturating_sub(field_u64(rest, "prepare")) as f64
                    / 1e6,
            );
            n_tcp += field_u64(rest, "tcp");
            n_udp += field_u64(rest, "udp");
            inq += field_u64(rest, "inq") as i64;
            outq += field_u64(rest, "outq") as i64;
            held_conns += field_u64(rest, "held_conns");
            held_bytes += field_u64(rest, "held_bytes");
        }
        n_fallback += field_u64(rest, "fallback");
        n_inel += field_u64(rest, "ineligible");
    }
    let mut outcomes: Vec<_> = outcomes.into_iter().collect();
    outcomes.sort();
    for v in [&mut pause, &mut park, &mut xfer] {
        v.sort_by(f64::total_cmp);
    }
    // A presumed commit has no HANDOVER row: the old generation died
    // before writing it.
    let committed = outcomes
        .iter()
        .filter(|(k, _)| k == "committed")
        .map(|(_, v)| *v)
        .sum::<u32>()
        + presumed;
    println!(
        "handovers: {outcomes:?}; committed {committed}/{upgrades} (presumed commits {presumed})"
    );
    println!(
        "transferred: {n_tcp} tcp connections, {n_udp} udp sessions; fallback to drain (not quiesced) {n_fallback}; ineligible (connecting) {n_inel}"
    );
    println!("kernel_bytes_at_park: in-queues {inq} B, out-queues {outq} B (summed over transferred sockets)");
    println!("userspace_bytes_carried: {held_bytes} B in {held_conns} connection transfers (non-zero only with --carry-held 1)");
    let line = |name: &str, v: &[f64]| {
        println!(
            "{name}_ms: p50 {:.2} p95 {:.2} max {:.2} (n={})",
            pct(v, 0.5),
            pct(v, 0.95),
            v.last().copied().unwrap_or(0.0),
            v.len()
        )
    };
    line("park", &park);
    line("protocol", &xfer);
    line("pause_park_to_adopt", &pause);
    if u64::from(committed) != upgrades {
        pass = false;
    }
    for (name, l) in &logs {
        let (k, rest) = kind_of(l);
        if k == "ABORTED" || k == "PARK_FAIL" || k == "ADOPT_FAIL" {
            println!("  {k} {rest} ({name})");
        }
    }

    // 4. UDP.
    let (mut sent, mut uniq, mut dup) = (0, 0, 0);
    for u in udp_out {
        sent += u.sent;
        uniq += u.uniq;
        dup += u.dup;
    }
    let ports = ports.lock().unwrap();
    let recreated: usize = ports.values().map(|s| s.len().saturating_sub(1)).sum();
    let uopen_later = logs.iter().filter(|(_, l)| kind_of(l).0 == "UOPEN").count();
    let udrops = logs.iter().filter(|(_, l)| kind_of(l).0 == "UDROP").count();
    println!(
        "udp: {} clients, {sent} requests, {} answered, {} unanswered, {dup} duplicated; backend source ports per client {:?}; sessions re-created {recreated}; UOPEN rows {uopen_later}; proxy drops {udrops}",
        udp_out.len(),
        uniq,
        sent - uniq,
        ports.values().map(HashSet::len).collect::<Vec<_>>()
    );
    if dup > 0 || recreated > 0 {
        pass = false;
    }
    println!("VERDICT {label}: {}", if pass { "PASS" } else { "FAIL" });
    pass
}
