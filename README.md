# portdisco

A fast, two-phase TCP sampler that discovers active IPv4 network blocks. It quickly samples candidate /16s and then dives into /24s to determine which ranges are actively hosting services, finally aggregating the discovered /24s into minimal CIDR blocks.

## How it works

portdisco runs in two phases:

1. Phase 1 (/16 sampling):
   - Expands the provided prefixes (defaults to RFC1918 ranges 10/8, 172.16/12, 192.168/16) into constituent /16s.
   - Randomly samples a small number of /24s inside each /16 and probes a tiny host sample per /24 (TCP connect) on a set of ports.
   - If any probes succeed, the /16 is considered "active" and carried into phase 2.

2. Phase 2 (/24 probing):
   - For all active /16s, enumerates all /24s in those /16s.
   - Samples a random set of hosts per /24 with concurrent TCP dials to the configured ports.
   - All /24s with any successful probe are collected and aggregated into minimal CIDRs for output.

Internally:
- Concurrency is bounded per-/24 via a semaphore; global worker counts control fan-out.
- Sampling varies between runs.

## Installation

Prerequisites: Go 1.21+ (tested on Go 1.25) and a network where you are permitted to run TCP connection attempts.

- Build a binary:
  - Using Go: `go build -o portdisco ./cmd`
  - Using Make: `make` (runs the binary with defaults; modify Makefile to suit your workflow)

- Run from source:
  - `go run ./cmd/...` (note: avoid naming your output binary `cmd` to prevent path conflicts)

## Usage

Basic run:

- `./portdisco`

By default, the tool auto-detects your local IPv4 interface networks and scans only those. If auto-detection finds nothing, it falls back to private RFC1918 ranges (10/8, 172.16/12, 192.168/16). You can always override with `-prefixes` to scan exactly what you want. If you want to ensure it only scans local interfaces and never falls back, use `-local-only`.

Examples:

- Scan your home LAN /24 for common ports:
  - `go run ./cmd/... -prefixes 192.168.1.0/24 -ports 80,443,22 -log=debug`

- Scan an enterprise 10/8 but limit initial sampling and increase timeout:
  - `go run ./cmd/... -prefixes 10.0.0.0/8 -sample16-init 6 -sample16-max 18 -timeout 1s -workers 800 -log=info`

- Focus on web ports with a modest concurrency per /24:
  - `go run ./cmd/... -prefixes 172.16.0.0/12 -ports 80,443 -max-concurrency 64`

Flags:
- `-log`                 log level: debug, info, warn, error, fatal, panic (default: info)
- `-workers`             number of concurrent workers feeding /16 and /24 tasks (default: 100)
- `-sample16-init`       initial number of /24s to sample per /16 in phase 1 (default: 10)
- `-sample16-max`        max number of /24s to sample per /16 in phase 1 (adaptive; default: 20)
- `-sample24`            number of hosts to sample per /24 in phase 2 (default: 10)
- `-max-concurrency`     max concurrent dials per /24 probe (default: 64; cap: 512)
- `-ports`               comma-separated TCP ports to probe (default: Nmap top 100 TCP ports)
- `-top-ports`           use built-in Nmap Top N TCP ports; allowed values: 100. If >0, overrides -ports (default: 0)
- `-timeout`             per-dial timeout (default: 500ms)
- `-prefixes`            comma-separated CIDR prefixes to scan (default: auto-detected local IPv4 networks; if none found, falls back to 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)
- `-local-only`          only scan auto-detected local IPv4 networks; if none are detected, do not fall back and exit with an error

Output:
- With `-log=debug`, progress is verbose. Discovered active /24s are aggregated to minimal CIDRs and printed at the end, e.g.:
  - Active routable blocks (aggregated):
    - 10.1.4.0/22
    - 10.1.8.0/24

## Troubleshooting

- No active /16s found. Nothing to do.
  - The default prefixes are private and may not be reachable from your host unless you’re on those networks.
  - Provide reachable networks with `-prefixes`, e.g. `-prefixes 192.168.1.0/24`.
  - Consider increasing `-timeout` and adjusting `-ports` to services likely to be open in your environment.

- Build command errors like "output cmd already exists and is a directory":
  - Avoid building with `-o cmd` or `go build ./cmd/...` in a way that collides with the cmd directory. Use `go build -o portdisco ./cmd` instead.

- Firewalls/NAT:
  - Outbound TCP may be filtered or rate-limited. Tune `-workers`, `-max-concurrency`, and `-timeout` accordingly.

## License
If a LICENSE file is not present, treat this as proprietary or contact the maintainer for licensing terms.
