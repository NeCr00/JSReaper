# JSReaper

Smart JavaScript asset discovery tool for recon and bug bounty.

Takes discovered JavaScript URLs and generates realistic hidden asset candidates — source maps, unhashed bundles, chunk siblings, framework companions — based on patterns in the URLs you already have. No blind wordlists.

**Requirements:** Python 3.7+ (stdlib only, no installs)

---

## How it works

You feed it JS URLs you already found during recon. The tool works in two phases:

**1. Analysis** — Parses every URL to extract structure: content hashes, chunk numbers, separators, and framework fingerprints (Next.js, Nuxt, Webpack, Vite, CRA). It also cross-analyses your whole input to confirm a shared build hash and detect missing chunk IDs (e.g. chunks 100–200 exist but 150 is missing → 150 likely exists too).

**2. Mutation** — For each URL it runs targeted strategies based on what it found: strips the hash, appends `.map`, removes `.min`, generates adjacent/gap chunk IDs with the confirmed build hash, adds framework companions (runtime, polyfills, common), and suggests named siblings.

Every candidate gets a confidence score (0–100). Source maps score 95, hash removals 85, speculative guesses like `.bak` files score 18. The result is a ranked list of URLs tied to patterns you actually observed — not a generic wordlist.

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
| `--min-score N` | Only show candidates with confidence ≥ N (0–100) |
| `--categories X,Y` | Filter by category (see below) |
| `--plain` | URLs only — pipe-safe output |
| `--json` | Structured JSON output |
| `--no-color` | Disable ANSI colors |

---

## Categories

| Category | What it finds |
|---|---|
| `SOURCE_MAP` | `.js.map` files — expose source code and paths |
| `HASH` | Dehashed / non-minified variants |
| `COMPANION` | Webpack runtime, polyfills, common chunks |
| `CHUNK` | Adjacent and gap-fill chunk IDs |
| `SIBLING` | Other named bundles at the same path |
| `ENV` | Dev/staging/debug build variants |
| `BACKUP` | `.bak`, `.old`, versioned leftovers |
| `DIR` | Directory listing probes |

---

## Examples

```bash
# High-value only — source maps and companions, score 80+
python3 jsreaper.py -f urls.txt --min-score 80 --categories SOURCE_MAP,COMPANION

# Pipe directly to httpx to probe live
python3 jsreaper.py -f urls.txt --plain | httpx -silent -mc 200

# Save full JSON report
python3 jsreaper.py -f urls.txt --json -o results.json

# Save clean URL list of high-confidence candidates
python3 jsreaper.py -f urls.txt --plain --min-score 70 -o candidates.txt
```

---

## Output (default grouped view)

```
  Input    : 1106 URL(s)
  Hash     : a3f4b2c1 (8 chars, sep='.')
  Generated: 48255 candidates

  Source Maps  [1095 candidates]
  [ 95]  https://app.example.com/main.a3f4b2c1.chunk.js.map
         Source map for JS bundle (exposes source code, paths, comments)
  ...
```

Each candidate shows a confidence score (0–100) and a reason. Higher score = more likely to exist.

---

## Input format

Any plain-text file with one URL per line. Non-JS lines (HTML, JSON, images, etc.) are automatically skipped.

```
https://app.example.com/static/js/main.a3f4b2c1.chunk.js
https://app.example.com/static/js/vendors.2b3c4d5e.chunk.js
https://app.example.com/react-dom.production.min.js
# comments and blank lines are ignored
```
