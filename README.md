# JSReaper

Smart JavaScript asset discovery tool for recon and bug bounty.

Takes discovered JavaScript URLs and generates hidden asset candidates based on patterns observed in the target — build hash, chunk convention, framework fingerprint. No blind wordlists, no confidence scores, just pattern-aware mutations.

**Requirements:** Python 3.7+ (stdlib only, no installs)

---

## How it works

You feed it JS URLs you already found during recon. The tool works in two phases:

**1. Analysis** — Parses every URL to extract structure: content hashes, chunk numbers, separators, and framework fingerprints (Next.js, Nuxt, Webpack, Vite, CRA). It also cross-analyses your whole input to confirm a shared build hash and detect missing chunk IDs (e.g. chunks 100–200 exist but 150 is missing → 150 likely exists too).

**2. Mutation** — For each URL it runs targeted strategies based on what it found: strips the hash, appends `.map`, removes `.min`, generates adjacent/gap chunk IDs with the confirmed build hash, adds framework companions (runtime, polyfills, common), suggests named siblings, and probes for sensitive functionality bundles (payments, admin, auth, export, etc.) using the target's exact naming convention.

Every candidate is derived from what the target actually uses — not guessed from a generic wordlist.

---

## Usage

```bash
# Single URL
python3 jsreaper.py -u "https://app.example.com/static/js/main.a3f4b2c1.chunk.js"

# File of URLs (one per line)
python3 jsreaper.py -f urls.txt
```

---

## Flags

| Flag | Description |
|---|---|
| `-u URL` | Single JS URL |
| `-f FILE` | File of JS URLs, one per line |
| `-o FILE` | Save results to file |
| `--categories X,Y` | Filter by category (see below) |
| `--plain` | URLs only — pipe-safe output |
| `--json` | Structured JSON output |
| `--no-color` | Disable ANSI colors |

---

## Categories

| Category | What it finds |
|---|---|
| `SOURCE_MAP` | `.js.map` files — expose source code, paths, and comments |
| `SENSITIVE` | Hidden bundles for payments, admin, auth, export, webhooks, etc. |
| `COMPANION` | Webpack runtime, polyfills, framework-specific chunks |
| `HASH` | Dehashed and non-minified variants |
| `SIBLING` | Other named bundles at the same path |
| `CHUNK` | Adjacent numeric chunks and confirmed sequence gaps |

---

## Examples

```bash
# Pipe directly to httpx to probe live
python3 jsreaper.py -f urls.txt --plain | httpx -silent -mc 200

# Source maps and sensitive bundles only
python3 jsreaper.py -f urls.txt --categories SOURCE_MAP,SENSITIVE

# Save full JSON report
python3 jsreaper.py -f urls.txt --json -o results.json

# Save clean URL list
python3 jsreaper.py -f urls.txt --plain -o candidates.txt

# Feed chunk candidates directly to ffuf
python3 jsreaper.py -f urls.txt --categories CHUNK --plain | ffuf -u FUZZ -w -
```

---

## Input format

Any plain-text file with one URL per line. Non-JS lines (HTML, JSON, images, etc.) are automatically skipped.

```
https://app.example.com/static/js/main.a3f4b2c1.chunk.js
https://app.example.com/static/js/vendors.2b3c4d5e.chunk.js
https://app.example.com/react-dom.production.min.js
# comments and blank lines are ignored
```
