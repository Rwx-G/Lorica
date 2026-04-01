# NFR Validation Guide

Manual validation procedures for non-functional requirements that cannot be verified in the standard E2E test suite (they require sustained load on a real Linux system).

## Prerequisites

- Linux x86_64 machine (VM or bare metal)
- Lorica installed from `.deb` package and running
- At least one route + backend configured
- Tools: `curl`, `python3` (for the backend stub), standard coreutils

## Running the validation

```bash
# Copy the script to the target machine and run it
chmod +x nfr-validate.sh
sudo ./nfr-validate.sh
```

The script:
1. Starts a lightweight Python HTTP backend on port 8900
2. Creates a test route via the API
3. Runs **NFR2** (10k concurrent connections) and **NFR11** (memory soak test)
4. Produces a structured report on stdout
5. Cleans up the test route and backend

## NFR2: 10,000 Concurrent Connections

**Requirement:** Each worker shall support 10,000+ concurrent connections.

**Method:** Open 10,000 TCP connections to the proxy port in parallel using a background connection pool, then verify:
- At least 95% of connections succeed
- The proxy remains responsive (a health check returns 200 during the test)
- No OOM or crash

**Pass criteria:**
- `connections_established >= 9500`
- `health_check_during_load = 200`
- `proxy_alive_after = true`

## NFR11: Memory Stability

**Requirement:** Memory usage shall remain stable over time with no unbounded growth.

**Method:** Send sustained traffic (100 req/s) for 10 minutes, sampling RSS memory every 30 seconds. Then compute:
- Linear regression slope of RSS over time
- Maximum RSS delta from start to end

**Pass criteria:**
- `rss_slope_kb_per_min < 100` (less than 100 KB/min growth)
- `rss_delta_mb < 20` (total growth under 20 MB over the test)
- No OOM kill

## Output format

The script writes a JSON report to `nfr-report-<timestamp>.json` and a human-readable summary to stdout. Share either with the development team for documentation.
