# airlock 🛡️

**A high-throughput, read-ahead streaming proxy, rolling DVR jitter shield, and single-upstream arbiter in safe Rust.**

[![CI](https://github.com/charles-adedotun/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/charles-adedotun/airlock/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![Zero Unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Binary Size](https://img.shields.io/badge/binary-4.0MB-brightgreen.svg)]()

---

## The Problem
Self-hosted media consumers and IPTV subscribers face three critical frustrations:
1. **WAN Jitter & Buffering**: Upstream IPTV connections freeze or drop on transient packet loss.
2. **Strict Single-Connection Account Bans**: Providers permanently ban accounts opening concurrent sockets during rapid channel zapping or multi-room streaming.
3. **Sports Spoiler Latency**: Heavy static buffering delays live games by 30+ seconds, ruining matches when mobile alerts arrive early.

## The Solution: `airlock`
`airlock` sits transparently between your media players (**Android TV ExoPlayer, Apple TV, Hisense VIDAA, TiviMate, VLC, Plex, Jellyfin**) and upstream video sources:

* **Dual-Tier Memory-Conscious Storage**:
  - **Live TV**: Transient **$< 32\text{ MB}$ RAM ring buffer** delivering sub-second zapping (< 450ms) via instantaneous PAT/PMT/IDR keyframe bursts.
  - **Rolling 50–200 GB DVR**: Automatically records and indexes watched content (Live and VOD) with zero manual scheduling.
  - **Linux Page-Cache Ejection**: Calls `posix_fadvise(POSIX_FADV_DONTNEED)` after every segment flush so multi-gigabyte streams never monopolize host system RAM.
* **Strict Single-Upstream Arbiter**: Mathematically guarantees $\le 1$ concurrent upstream connection with an asynchronous teardown barrier and 300ms zapping debounce.
* **Razor-Edge Sports Target ($\le 2.5\text{s}$)**: Maintains a 1.5s–2.5s lead behind real-world broadcast, with automated $1.05\times$ audio-pitch-preserved catch-up after network jitter.
* **Hardened Security**: Custom `SafeDnsResolver` blocking SSRF pivots into RFC 1918 LANs, cloud metadata, and Tailscale CGNAT (`100.64.0.0/10`), alongside automated URL credential masking.

---

## Quickstart

### Installation & Run

```bash
# Clone and build
git clone https://github.com/charles-adedotun/airlock.git
cd airlock
cargo build --release

# Run with defaults (port 8795, 100 GB rolling window)
./target/release/airlock \
  --listen 0.0.0.0:8795 \
  --upstream http://your-provider.org \
  --max-storage-gb 100 \
  --sports-latency-sec 2.0
```

### CLI Reference

| Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `-l, --listen` | `AIRLOCK_LISTEN` | `0.0.0.0:8795` | Bind address for HTTP gateway |
| `-u, --upstream` | `AIRLOCK_UPSTREAM` | `http://line.ottcst.org` | Upstream provider base URL |
| `-c, --cache-dir` | `AIRLOCK_CACHE_DIR` | `~/.cache/airlock/media` | Storage directory for rolling DVR |
| `--max-storage-gb` | `AIRLOCK_MAX_STORAGE_GB` | `100` | Rolling cache ceiling (50–200 GB) |
| `--min-disk-free-gb` | `AIRLOCK_MIN_DISK_FREE_GB` | `10` | Emergency free disk floor |
| `--sports-latency-sec` | `AIRLOCK_SPORTS_LATENCY_SEC` | `2.0` | Target live sports latency |

---

## Integration with Players

### 1. TiviMate / IPTV Apps
Set your M3U playlist URL to:
```
http://<your-host>:8795/playlist.m3u8
```

### 2. Plex / Jellyfin Live TV & DVR
Airlock acts as an HDHomeRun tuner device:
* Tuner URL: `http://<your-host>:8795`
* Lineup endpoint: `http://<your-host>:8795/lineup.json`
* Device XML: `http://<your-host>:8795/device.xml`

---

## Verification & Architecture Standards

```bash
# Run unit, chaos, range, and container test suites (58 tests)
cargo test

# Strict safety and linter verification
cargo clippy -- -D warnings
cargo fmt --check

# Microbenchmarks
cargo bench --bench ring_bench
```

- **Safety**: Built under `#![forbid(unsafe_code)]` with zero `unsafe` blocks.
- **Reliability**: Tested under 2000ms WAN jitter stalls, socket drops, and 10 req/s zapping storms.
- **Resource Footprint**: Statically linked **4.0 MB binary** using $< 32\text{ MB}$ RSS.

---

## License
MIT License. Crafted for homelab and high-performance media delivery.
