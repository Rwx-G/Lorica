# Lorica Benchmark

Reproducible proxy benchmark using [oha](https://github.com/hatoo/oha) in a Docker topology.

## Topology

```
[oha runner] --> [lorica:8080] --round-robin--> [backend1:80]
                                            \-> [backend2:80]
```

All containers run on the same Docker network. Backends are Python HTTP servers returning a small JSON response (~100 bytes).

## Quick Start

```bash
cd bench
./run.sh --build
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--duration N` | 30 | Test duration in seconds |
| `--connections N` | 100 | Concurrent connections |
| `--workers N` | 0 | Lorica worker processes (0 = single-process) |
| `--waf` | off | Enable WAF detection mode on the route |
| `--cache` | off | Enable response caching on the route |
| `--build` | off | Force rebuild all Docker images |

## Example Runs

```bash
# Baseline: single-process, no WAF, no cache
./run.sh --build --duration 60 --connections 200

# Multi-worker (4 workers)
./run.sh --workers 4 --duration 60 --connections 200

# With WAF overhead
./run.sh --waf --duration 60 --connections 200

# With caching (measures cache hit path)
./run.sh --cache --duration 60 --connections 200
```

## Output

Each run produces:
- `results/bench-<timestamp>.json` - full oha JSON output
- `results/bench-<timestamp>.txt` - human-readable summary
- `results/LATEST.txt` / `LATEST.json` - symlinks to most recent run

## Comparing Runs

```bash
# Side-by-side comparison
diff results/bench-20260402-1000.txt results/bench-20260402-1100.txt

# Extract RPS from all runs
for f in results/*.json; do
    echo "$(basename $f): $(jq -r '.summary.requestsPerSec' $f) req/s"
done
```

## Methodology Notes

- Backends are minimal (Python HTTP server, ~0.1ms response time) to isolate proxy overhead
- All traffic stays within Docker network (no host networking overhead)
- oha uses HTTP/1.1 keepalive connections by default
- Results vary by host CPU, Docker runtime, and system load
- Run benchmarks on a quiet machine for consistent results
- The `results/` directory is gitignored
