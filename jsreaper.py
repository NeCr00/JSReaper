#!/usr/bin/env python3
"""
jsreaper.py  ─  Smart JavaScript Asset Discovery Tool
========================================================
v1.0.0

Generates high-quality candidate JavaScript endpoints from discovered URLs
using pattern-aware mutation — NOT blind wordlist expansion.

Every candidate is derived from a characteristic observed in the target:
  hash patterns, directory structure, framework fingerprints, chunk naming,
  sibling bundle conventions, build system artifacts.

Recognized build ecosystems:
  Next.js, Create React App, Nuxt.js, Angular, Vite, generic Webpack,
  Rollup/custom pipelines.

Usage
─────
  # Single URL
  python jsreaper.py -u "https://app.example.com/static/js/main.a3f4b2c1.chunk.js"

  # File of URLs
  python jsreaper.py -f urls.txt

  # Filter by minimum confidence and save results
  python jsreaper.py -f urls.txt --min-score 60 -o candidates.txt

  # Machine-readable JSON (pipe to jq, save for later)
  python jsreaper.py -f urls.txt --json -o results.json

  # URL-only output (pipe directly to httpx / curl / ffuf)
  python jsreaper.py -f urls.txt --plain

  # Show only specific categories
  python jsreaper.py -f urls.txt --categories SOURCE_MAP,COMPANION,HASH
"""

from __future__ import annotations

import os
import re
import sys
import json
import argparse
import textwrap
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse
from pathlib import PurePosixPath


# ══════════════════════════════════════════════════════════════════════════════
#  VOCABULARY CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

TOOL_VERSION = "1.0.0"

# Route / feature names commonly found in lazy-loaded JS chunks
ROUTE_NAMES: List[str] = [
    "home", "index", "about", "contact",
    "login", "logout", "register", "signup",
    "dashboard", "admin", "profile", "settings",
    "search", "help", "error", "404", "500",
    "not-found", "forbidden", "unauthorized",
    "checkout", "cart", "orders", "products",
    "account", "auth", "user", "users",
    "overview", "reports", "analytics", "docs",
    "support", "terms", "privacy", "wizard",
    "onboarding", "internal", "debug",
]

# Sibling bundle basenames that appear together in virtually every bundled app
SIBLING_BASES: List[str] = [
    "main", "app", "index",
    "vendor", "vendors",
    "runtime", "runtime-main",
    "polyfills",
    "bootstrap", "common", "commons",
    "shared", "core", "lib",
    "utils", "init", "entry",
    "framework", "styles", "scripts",
    "chunk", "bundle",
]

# Well-known Webpack infrastructure filenames (semantic part only, no hash/ext)
WEBPACK_INFRA: List[str] = [
    "webpack-runtime", "webpack", "webpack-bundle",
    "vendors~main", "vendors~app", "vendors~async",
    "vendors", "vendor",
    "runtime-main", "runtime",
    "commons", "common",
    "polyfills",
]

# Framework-specific companion files grouped by (path_fragment → [filenames])
# Path fragments are checked with 'in' against the URL path.
FRAMEWORK_COMPANIONS: Dict[str, Dict[str, List[str]]] = {
    "nextjs": {
        "_next/static/chunks": [
            "webpack.js", "main.js", "polyfills.js",
            "framework.js", "commons.js",
        ],
        "_next/static/chunks/pages": [
            "_app.js", "_error.js", "index.js", "404.js",
            "login.js", "dashboard.js", "admin.js",
        ],
        "_next/static/runtime": [
            "main.js", "webpack.js", "polyfills.js",
        ],
    },
    "nuxt": {
        "_nuxt": [
            "app.js", "vendors~app.js", "runtime.js",
            "commons.app.js", "index.js",
            "pages/index.js", "layouts/default.js",
        ],
    },
    "cra": {      # Create React App (Webpack)
        "static/js": [
            "main.chunk.js", "runtime-main.js",
            "0.chunk.js", "1.chunk.js", "2.chunk.js", "3.chunk.js",
            "vendors~main.chunk.js", "vendors~async.chunk.js",
        ],
    },
    "angular": {  # Angular CLI — same directory, no specific path prefix
        "": [
            "main.js", "polyfills.js", "runtime.js",
            "vendor.js", "vendors.js", "styles.js",
            "common.js", "scripts.js",
        ],
    },
    "vite": {
        "assets": [
            "index.js", "vendor.js",
        ],
    },
}

# Tokens that look hash-like but are actually meaningful keywords.
# Route names are included because lazy-HOME.chunk.js has a route name, not a hash.
_NOT_HASH: Set[str] = {
    "min", "dev", "prod", "app", "lib", "js", "css",
    "src", "map", "chunk", "bundle", "runtime", "vendor",
    "main", "index", "common", "async", "lazy", "core",
    "utils", "polyfills", "bootstrap", "worker", "sw",
    "service", "module", "es5", "es6", "es2015", "es2020",
    "umd", "cjs", "esm", "ssr", "client", "server", "legacy",
    "test", "spec", "staging", "debug", "local", "next",
    "nuxt", "react", "angular", "vue", "svelte",
    # Build environment qualifiers — 10–11 char lowercase, would pass alnum heuristic
    "production", "development",
    # Route names — seen in lazy-<route>.chunk.js patterns
    "home", "about", "contact", "login", "logout", "register", "signup",
    "dashboard", "admin", "profile", "settings", "search", "help",
    "error", "checkout", "cart", "orders", "products", "account",
    "auth", "user", "users", "overview", "reports", "analytics",
    "docs", "support", "terms", "privacy", "wizard", "onboarding",
    "internal", "forbidden", "unauthorized", "not", "found",
}

# Qualifiers inserted before .js to create backup/legacy variants
BACKUP_QUALIFIERS: List[str] = [
    "bak", "old", "orig", "backup", "copy", "v1", "v2",
]

# Qualifiers inserted before .js to create environment variants
ENV_QUALIFIERS: List[str] = [
    "dev", "development", "prod", "production",
    "staging", "test", "debug", "local",
]

# Alternative asset directories tried when generating dir-based candidates
ALT_ASSET_DIRS: List[str] = [
    "/js/", "/assets/", "/static/js/", "/dist/js/",
    "/build/js/", "/public/js/", "/out/js/",
]


# ══════════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedJS:
    """All extracted attributes from a single JavaScript URL."""
    original_url: str
    scheme:       str
    host:         str
    path:         str          # /static/js/main.abc123.chunk.js
    directory:    str          # /static/js/
    filename:     str          # main.abc123.chunk.js
    stem:         str          # main.abc123.chunk  (everything before final .js)
    basename:     str          # main  (hash + decorators stripped)
    extension:    str          # .js  or  .js.map

    hash:         Optional[str]   # "abc123"
    hash_len:     Optional[int]   # 6
    hash_sep:     Optional[str]   # "." or "-" — separator around the hash
    version:      Optional[str]   # "1.2.3" if a version string is found
    chunk_num:    Optional[int]   # 42 if basename is a pure integer

    name_parts:   List[str]       # stem split by separators
    separators:   List[str]       # separators found in stem (ordered, unique)

    framework:    Optional[str]   # nextjs | cra | nuxt | angular | vite
    build_system: Optional[str]   # webpack | vite | rollup

    is_minified:  bool
    has_chunk:    bool            # .chunk.js or -chunk.js suffix
    has_bundle:   bool            # .bundle.js or -bundle.js suffix

    path_segments: List[str]      # path directory components
    is_lazy:      bool            # lazy-* prefix pattern
    lazy_target:  Optional[str]   # "home" from lazy-home.chunk.js


@dataclass
class Candidate:
    """One generated candidate JS URL with full discovery metadata."""
    url:        str
    strategy:   str   # short machine key, e.g. "source_map"
    reason:     str   # human-readable explanation
    confidence: int   # 0–100
    category:   str   # SOURCE_MAP | HASH | COMPANION | CHUNK | SIBLING | ENV | BACKUP | DIR
    source_url: str   # which input URL triggered this candidate

    def to_dict(self) -> dict:
        return {
            "url":        self.url,
            "confidence": self.confidence,
            "category":   self.category,
            "strategy":   self.strategy,
            "reason":     self.reason,
            "source_url": self.source_url,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  URL PARSING
# ══════════════════════════════════════════════════════════════════════════════

def _normalise(raw: str) -> str:
    """Add scheme when URL is protocol-relative or path-only."""
    raw = raw.strip()
    if raw.startswith("//"):
        return "https:" + raw
    if not raw.startswith(("http://", "https://")):
        if raw.startswith("/"):
            return "https://PLACEHOLDER" + raw
        return "https://PLACEHOLDER/" + raw
    return raw


def _is_hash(token: str) -> bool:
    """
    Heuristic: does this token look like a content/build hash?

    Strong signal: pure lowercase hex, 6–32 chars, not a known keyword.
    Weak signal:   lowercase alphanumeric, 8–16 chars.
    """
    if not token or token.lower() in _NOT_HASH:
        return False
    n = len(token)
    if re.fullmatch(r"[a-f0-9]+", token) and 6 <= n <= 32:
        return True
    if re.fullmatch(r"[a-z0-9]+", token) and 8 <= n <= 16:
        return True
    return False


def _extract_hash(stem: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Scan a stem for an embedded content hash.

    Tries ".", "-", "_" as separators; scans right-to-left because hashes
    appear near the end (name.HASH.chunk, not HASH.name.chunk).

    Returns (hash_string, separator) or (None, None).
    """
    for sep in (".", "-", "_"):
        parts = stem.split(sep)
        # Skip index 0 — that's the semantic name, not the hash
        for part in reversed(parts[1:]):
            if _is_hash(part):
                return part, sep
    return None, None


def _extract_version(stem: str) -> Optional[str]:
    """Extract a version string such as v1.2.3 or 2.0 from a stem."""
    m = re.search(r"(?<=[._-])(v?\d+(?:[._]\d+){1,3})(?=[._-]|$)", stem, re.I)
    if m:
        v = m.group(1)
        # Reject short pure-hex strings (could be a hash)
        if re.fullmatch(r"[a-f0-9]+", v.lstrip("vV")):
            return None
        return v
    return None


def _split_stem(stem: str) -> Tuple[List[str], List[str]]:
    """
    Split stem into parts and record the separators used.
    Returns (parts_list, unique_separators_in_order).
    """
    tokens = re.split(r"([._-])", stem)
    parts  = [t for t in tokens[::2]  if t]
    seps   = [t for t in tokens[1::2] if t]
    seen: Set[str] = set()
    unique_seps: List[str] = []
    for s in seps:
        if s not in seen:
            unique_seps.append(s)
            seen.add(s)
    return parts, unique_seps


def _detect_framework(path: str, filename: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Detect frontend framework and bundler from URL path characteristics.
    Returns (framework_key, build_system_key).
    """
    pl = path.lower()
    fl = filename.lower()

    if "_next/static" in pl:
        return "nextjs", "webpack"
    if "/_nuxt/" in pl or pl.startswith("/_nuxt/"):
        return "nuxt", "webpack"
    if "static/js/" in pl and (".chunk.js" in fl or "runtime-main" in fl):
        return "cra", "webpack"
    if "/assets/" in pl and re.search(r"-[a-zA-Z0-9]{8}\.js$", filename):
        return "vite", "vite"
    if fl.startswith(("main.", "polyfills.", "runtime.")):
        if any(kw in pl for kw in ["/dist/", "/build/", "angular", "/ng-"]):
            return "angular", "webpack"
    if "webpack" in fl or "vendors~" in fl or ".chunk.js" in fl:
        return None, "webpack"
    return None, None


def parse_js_url(raw: str) -> Optional[ParsedJS]:
    """
    Parse one raw JS URL string into a fully-structured ParsedJS.
    Returns None if the string is not a parseable JS asset URL.
    """
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    url = _normalise(raw)
    try:
        p = urlparse(url)
    except Exception:
        return None

    path = p.path
    if not path or path == "/":
        return None

    pp        = PurePosixPath(path)
    filename  = pp.name
    parent    = str(pp.parent)
    directory = (parent if parent != "/" else "") + "/"

    # Must be a JS file
    if filename.endswith(".js.map"):
        ext, stem = ".js.map", filename[:-7]
    elif filename.endswith(".js"):
        ext, stem = ".js", filename[:-3]
    else:
        return None

    # Detect decorator suffixes
    sl = stem.lower()
    is_minified = ".min" in sl or sl.endswith("-min")
    has_chunk   = sl.endswith(".chunk") or sl.endswith("-chunk")
    has_bundle  = sl.endswith(".bundle") or sl.endswith("-bundle")

    # Strip decorator suffixes to isolate semantic content
    clean = stem
    for suf in (".chunk", "-chunk", ".bundle", "-bundle", ".min", "-min"):
        if clean.lower().endswith(suf):
            clean = clean[: -len(suf)]

    hash_val, hash_sep = _extract_hash(clean)
    hash_len = len(hash_val) if hash_val else None
    version  = _extract_version(clean)

    # Strip hash to get the semantic basename
    basename = clean
    if hash_val and hash_sep:
        # Suffix position: name.HASH or name-HASH
        idx = clean.rfind(hash_sep + hash_val)
        if idx >= 0:
            basename = clean[:idx]
        # Prefix position edge case: HASH.name
        if not basename or not re.search(r"[a-zA-Z]", basename):
            idx2 = clean.find(hash_val + hash_sep)
            if idx2 == 0:
                basename = clean[len(hash_val) + 1:]

    basename = basename.strip("._-") or clean

    # Pure-numeric basename → chunk number
    chunk_num: Optional[int] = None
    if re.fullmatch(r"\d+", basename):
        try:
            chunk_num = int(basename)
        except ValueError:
            pass

    # Lazy-chunk pattern: lazy-home.chunk.js, lazy_dashboard.js
    lm = re.match(r"^lazy[_-](.+)$", basename, re.I)
    is_lazy     = bool(lm)
    lazy_target = lm.group(1) if lm else None

    name_parts, separators = _split_stem(stem)
    segments = [s for s in path.split("/") if s and s != filename]
    framework, build_system = _detect_framework(path, filename)

    host = p.netloc
    if host in ("PLACEHOLDER", ""):
        host = ""

    return ParsedJS(
        original_url  = raw,
        scheme        = p.scheme or "https",
        host          = host,
        path          = path,
        directory     = directory,
        filename      = filename,
        stem          = stem,
        basename      = basename,
        extension     = ext,
        hash          = hash_val,
        hash_len      = hash_len,
        hash_sep      = hash_sep,
        version       = version,
        chunk_num     = chunk_num,
        name_parts    = name_parts,
        separators    = separators,
        framework     = framework,
        build_system  = build_system,
        is_minified   = is_minified,
        has_chunk     = has_chunk,
        has_bundle    = has_bundle,
        path_segments = segments,
        is_lazy       = is_lazy,
        lazy_target   = lazy_target,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  URL BUILDING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _base_url(js: ParsedJS) -> str:
    """Return 'scheme://host' prefix (empty string for path-only URLs)."""
    return f"{js.scheme}://{js.host}" if js.host else ""


def _url_in_dir(js: ParsedJS, filename: str, directory: Optional[str] = None) -> str:
    """Construct a URL placing `filename` in `directory` (or js.directory)."""
    d = directory if directory is not None else js.directory
    if not d.endswith("/"):
        d += "/"
    return _base_url(js) + d + filename



# ══════════════════════════════════════════════════════════════════════════════
#  MUTATION STRATEGIES
#  Each strategy is a generator that yields Candidate objects.
#  They receive the ParsedJS and an optional `context` dict with cross-URL info.
# ══════════════════════════════════════════════════════════════════════════════

def mut_source_map(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: SOURCE_MAP
    Every minified or hashed bundle is almost always accompanied by a .map file.
    This is the highest-value mutation — source maps expose raw source code,
    comments, internal paths, and can reveal secrets and full route structure.
    """
    if js.extension == ".js.map":
        return  # Already a source map

    target = _url_in_dir(js, js.filename + ".map")
    yield Candidate(
        url        = target,
        strategy   = "source_map",
        reason     = "Source map for JS bundle (exposes source code, paths, comments)",
        confidence = 95 if (js.hash or js.is_minified) else 72,
        category   = "SOURCE_MAP",
        source_url = js.original_url,
    )


def mut_hash_removal(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: HASH
    Strip the detected content hash from the filename.
    Many CDN setups serve both hashed (cache-busted) and non-hashed versions.
    Non-hashed paths are often accessible on the origin server.
    """
    if not js.hash:
        return

    h = js.hash
    dec = ".chunk" if js.has_chunk else (".bundle" if js.has_bundle else "")
    min_dec = ".min" if js.is_minified else ""

    # Variant 1: basename + decorators, no hash
    name_no_hash = js.basename + min_dec + dec + js.extension
    url1 = _url_in_dir(js, name_no_hash)
    yield Candidate(
        url        = url1,
        strategy   = "hash_removal",
        reason     = f"Hash '{h}' removed — non-hashed path often accessible on origin",
        confidence = 85,
        category   = "HASH",
        source_url = js.original_url,
    )

    # Variant 2: if had .chunk or .bundle, also try completely bare
    if dec:
        name_bare = js.basename + min_dec + js.extension
        url2 = _url_in_dir(js, name_bare)
        if url2 != url1:
            yield Candidate(
                url        = url2,
                strategy   = "hash_removal_bare",
                reason     = f"Hash and chunk/bundle suffix both removed",
                confidence = 75,
                category   = "HASH",
                source_url = js.original_url,
            )


def mut_minified_toggle(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: MINIFIED
    Toggle between minified (.min.js) and non-minified (.js) variants.
    Non-minified bundles expose full variable names, comments, and logic.
    """
    dec = ".chunk" if js.has_chunk else (".bundle" if js.has_bundle else "")
    hash_part = (js.hash_sep + js.hash) if js.hash else ""

    if js.is_minified:
        # Non-minified version
        name = js.basename + hash_part + dec + ".js"
        yield Candidate(
            url        = _url_in_dir(js, name),
            strategy   = "minified_toggle",
            reason     = "Non-minified version of .min.js (may expose logic, comments)",
            confidence = 72,
            category   = "HASH",
            source_url = js.original_url,
        )
    else:
        # Minified version
        name = js.basename + hash_part + ".min" + dec + ".js"
        yield Candidate(
            url        = _url_in_dir(js, name),
            strategy   = "minified_toggle",
            reason     = "Minified variant — may exist alongside non-minified source",
            confidence = 55,
            category   = "HASH",
            source_url = js.original_url,
        )


def mut_extension_variants(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: EXTENSION
    Generate alternate extension patterns: .bundle.js, .chunk.js, .js.
    Useful when only one variant of a file has been discovered.
    """
    if js.extension == ".js.map":
        return

    hash_part = (js.hash_sep + js.hash) if js.hash else ""
    base = js.basename

    variants = []
    if not js.has_chunk:
        variants.append((base + hash_part + ".chunk.js",  "Chunk variant of observed file",  52))
    if not js.has_bundle:
        variants.append((base + hash_part + ".bundle.js", "Bundle variant of observed file", 48))

    for name, reason, score in variants:
        yield Candidate(
            url        = _url_in_dir(js, name),
            strategy   = "extension_variant",
            reason     = reason,
            confidence = score,
            category   = "HASH",
            source_url = js.original_url,
        )


def mut_framework_companions(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: COMPANION
    Emit well-known companion files for the detected framework.
    These are the files that build tools always produce alongside the main bundle.

    When a build hash is confirmed (from ctx), inject it into companion filenames
    to maximize accuracy — all files from the same build share the same hash.
    """
    fw = js.framework
    if not fw or fw not in FRAMEWORK_COMPANIONS:
        return

    confirmed_hash = ctx.get("confirmed_hash")
    confirmed_sep  = ctx.get("confirmed_hash_sep", ".")

    companion_map = FRAMEWORK_COMPANIONS[fw]

    for path_frag, filenames in companion_map.items():
        # Determine which directory these companions live in
        if path_frag == "":
            # Same directory as observed file
            target_dir = js.directory
        else:
            # Find the fragment in our URL
            if path_frag in js.path:
                idx = js.path.find(path_frag)
                target_dir = js.path[:idx + len(path_frag) + 1]
            else:
                # Build the directory from the host root
                target_dir = "/" + path_frag.lstrip("/") + "/"
                if not target_dir.endswith("/"):
                    target_dir += "/"

        for fname in filenames:
            # Emit with the confirmed build hash injected (if we have one)
            if confirmed_hash and not fname.endswith(".map"):
                # Insert hash into companion filename if it has a known pattern
                stem_part, _, ext_part = fname.rpartition(".")
                ext_part = "." + ext_part
                if stem_part.endswith(".chunk"):
                    inner = stem_part[:-6]
                    name_with_hash = inner + confirmed_sep + confirmed_hash + ".chunk" + ext_part
                elif stem_part.endswith(".bundle"):
                    inner = stem_part[:-7]
                    name_with_hash = inner + confirmed_sep + confirmed_hash + ".bundle" + ext_part
                else:
                    name_with_hash = stem_part + confirmed_sep + confirmed_hash + ext_part

                yield Candidate(
                    url        = _url_in_dir(js, name_with_hash, target_dir),
                    strategy   = f"{fw}_companion_hashed",
                    reason     = (f"{_fw_label(fw)} companion '{fname}'; "
                                  f"build hash '{confirmed_hash}' injected"),
                    confidence = 82,
                    category   = "COMPANION",
                    source_url = js.original_url,
                )

            # Always also emit the plain (no-hash) companion
            yield Candidate(
                url        = _url_in_dir(js, fname, target_dir),
                strategy   = f"{fw}_companion",
                reason     = f"{_fw_label(fw)} companion file: '{fname}'",
                confidence = 78,
                category   = "COMPANION",
                source_url = js.original_url,
            )


def mut_webpack_infra(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: WEBPACK_INFRA
    Generate well-known Webpack infrastructure filenames in the same directory.
    Applies when a Webpack build system is detected (or strongly implied by hash pattern).
    These files (runtime, vendors, commons) are almost always present in Webpack output.
    """
    if js.build_system != "webpack" and js.framework not in ("nextjs", "cra", "nuxt", "angular"):
        return

    confirmed_hash = ctx.get("confirmed_hash")
    confirmed_sep  = ctx.get("confirmed_hash_sep", ".")

    for infra_base in WEBPACK_INFRA:
        if infra_base == js.basename:
            continue  # Skip the file we already know about

        # With hash
        if confirmed_hash:
            for dec in [".chunk", ""]:
                name_h = infra_base + confirmed_sep + confirmed_hash + dec + ".js"
                yield Candidate(
                    url        = _url_in_dir(js, name_h),
                    strategy   = "webpack_infra_hashed",
                    reason     = (f"Webpack '{infra_base}' bundle; "
                                  f"build hash '{confirmed_hash}' injected"),
                    confidence = 74,
                    category   = "COMPANION",
                    source_url = js.original_url,
                )

        # Without hash (plain name)
        for dec in [".chunk.js", ".js"]:
            name_plain = infra_base + dec
            yield Candidate(
                url        = _url_in_dir(js, name_plain),
                strategy   = "webpack_infra_plain",
                reason     = f"Webpack infrastructure bundle: '{infra_base}'",
                confidence = 65,
                category   = "COMPANION",
                source_url = js.original_url,
            )


def mut_adjacent_chunks(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: CHUNK
    When a URL contains a numeric chunk ID (e.g. 2.abc123.chunk.js), generate
    adjacent chunk numbers. Webpack emits sequential numeric IDs for code-split
    chunks; missing numbers reveal undiscovered lazy-loaded route bundles.
    """
    num = js.chunk_num
    if num is None:
        return

    sep  = js.hash_sep or "."
    dec  = ".chunk" if js.has_chunk else ""
    ext  = ".js"

    confirmed_hash = ctx.get("confirmed_hash")
    gap_set = set(ctx.get("chunk_gaps", []))

    # Emit confirmed gap chunks FIRST — they score higher and should win deduplication
    # over the adjacent-chunk variants that cover the same numbers.
    for gap in sorted(gap_set):
        if gap == num:
            continue
        name = str(gap) + (sep + confirmed_hash if confirmed_hash else "") + dec + ext
        yield Candidate(
            url        = _url_in_dir(js, name),
            strategy   = "chunk_gap_fill",
            reason     = (f"Gap chunk #{gap} confirmed by multi-URL analysis "
                          f"(observed sequence: {ctx.get('chunk_sequence', [])})"),
            confidence = 82,
            category   = "CHUNK",
            source_url = js.original_url,
        )

    # Generate ±5 neighbors, weighting closer ones more highly
    for delta in range(-5, 6):
        if delta == 0:
            continue
        neighbor = num + delta
        if neighbor < 0:
            continue

        score = 80 - abs(delta) * 6   # 74 for ±1, 68 for ±2, …, 50 for ±5

        if confirmed_hash:
            name_h = str(neighbor) + sep + confirmed_hash + dec + ext
            yield Candidate(
                url        = _url_in_dir(js, name_h),
                strategy   = "adjacent_chunk_hashed",
                reason     = (f"Adjacent chunk #{neighbor} to observed #{num}; "
                              f"same build hash '{confirmed_hash}'"),
                confidence = score,
                category   = "CHUNK",
                source_url = js.original_url,
            )

        name_plain = str(neighbor) + dec + ext
        yield Candidate(
            url        = _url_in_dir(js, name_plain),
            strategy   = "adjacent_chunk_plain",
            reason     = f"Adjacent chunk #{neighbor} to observed #{num}",
            confidence = score - 8,
            category   = "CHUNK",
            source_url = js.original_url,
        )


def mut_sibling_bases(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: SIBLING
    Generate common sibling bundle names in the same directory.
    Applies to named (non-numeric, non-lazy) chunks.
    Skips names already observed in the input set.
    """
    if js.chunk_num is not None:
        return  # Numeric chunks handled by mut_adjacent_chunks

    known = ctx.get("known_basenames", set())
    confirmed_hash = ctx.get("confirmed_hash")
    sep  = js.hash_sep or "."
    dec  = ".chunk" if js.has_chunk else ""

    for sibling in SIBLING_BASES:
        if sibling == js.basename or sibling in known:
            continue

        # With confirmed build hash
        if confirmed_hash:
            name_h = sibling + sep + confirmed_hash + dec + ".js"
            yield Candidate(
                url        = _url_in_dir(js, name_h),
                strategy   = "sibling_hashed",
                reason     = (f"Common sibling bundle '{sibling}'; "
                              f"same build hash '{confirmed_hash}'"),
                confidence = 68,
                category   = "SIBLING",
                source_url = js.original_url,
            )

        # Plain (no hash)
        for ext_variant in ([dec + ".js", ".js"] if dec else [".js"]):
            name_plain = sibling + ext_variant
            yield Candidate(
                url        = _url_in_dir(js, name_plain),
                strategy   = "sibling_plain",
                reason     = f"Common sibling bundle name: '{sibling}'",
                confidence = 58,
                category   = "SIBLING",
                source_url = js.original_url,
            )


def mut_route_siblings(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: ROUTE
    When a lazy-loaded chunk is named after a route (e.g. lazy-home.chunk.js),
    generate candidates for other common routes. Route chunks reveal hidden
    application functionality and undocumented sections of the app.
    """
    # Numeric chunks are handled exclusively by mut_adjacent_chunks — never route siblings.
    if js.chunk_num is not None:
        return

    if not js.is_lazy:
        # Also applies to named route chunks without lazy- prefix,
        # e.g. pages/home.js → try pages/admin.js
        if js.basename.lower() not in ROUTE_NAMES:
            return

    target = js.lazy_target or js.basename
    known  = ctx.get("known_basenames", set())

    confirmed_hash = ctx.get("confirmed_hash")
    sep  = js.hash_sep or "."
    dec  = ".chunk" if js.has_chunk else ""

    for route in ROUTE_NAMES:
        if route == target or route in known:
            continue

        # Reconstruct with same lazy prefix if present
        prefix = "lazy" + (js.basename[4] if js.is_lazy else "-")   # lazy- or lazy_
        if js.is_lazy:
            sibling_base = prefix + route
        else:
            sibling_base = route

        if confirmed_hash:
            name_h = sibling_base + sep + confirmed_hash + dec + ".js"
            yield Candidate(
                url        = _url_in_dir(js, name_h),
                strategy   = "route_sibling_hashed",
                reason     = (f"Route chunk sibling: '{route}' "
                              f"(observed route: '{target}', same pattern)"),
                confidence = 62,
                category   = "SIBLING",
                source_url = js.original_url,
            )

        name_plain = sibling_base + dec + ".js"
        yield Candidate(
            url        = _url_in_dir(js, name_plain),
            strategy   = "route_sibling_plain",
            reason     = f"Route chunk sibling: '{route}' (observed route: '{target}')",
            confidence = 55,
            category   = "SIBLING",
            source_url = js.original_url,
        )


def mut_env_variants(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: ENV
    Generate environment-specific variants: .dev.js, .prod.js, .staging.js.
    Development builds are often left on staging servers or internal environments
    and can expose debug output, commented logic, or internal endpoints.
    """
    if js.extension == ".js.map":
        return

    for qual in ENV_QUALIFIERS:
        if qual in js.basename.lower() or qual in js.stem.lower():
            continue  # Already contains this qualifier

        # basename.QUALIFIER.js
        name = js.basename + "." + qual + ".js"
        yield Candidate(
            url        = _url_in_dir(js, name),
            strategy   = "env_variant",
            reason     = f"Environment variant '{qual}' — may expose debug/dev build",
            confidence = 32,
            category   = "ENV",
            source_url = js.original_url,
        )


def mut_backup_variants(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: BACKUP
    Generate backup and legacy filename variants.
    Files like .bak, .old, .orig are sometimes left on servers after deployments.
    Legacy versioned names (v1, v2) reveal historical application behaviour.
    """
    if js.extension == ".js.map":
        return

    for qual in BACKUP_QUALIFIERS:
        if qual in js.basename.lower():
            continue

        # basename.QUAL.js
        name_qual  = js.basename + "." + qual + ".js"
        yield Candidate(
            url        = _url_in_dir(js, name_qual),
            strategy   = "backup_variant",
            reason     = f"Backup/legacy variant: '{qual}' qualifier",
            confidence = 22,
            category   = "BACKUP",
            source_url = js.original_url,
        )

    # basename.js.bak (appended to full filename)
    for suf in (".bak", ".old", ".orig", "~", ".tmp"):
        yield Candidate(
            url        = _url_in_dir(js, js.filename + suf),
            strategy   = "backup_suffix",
            reason     = f"Backup suffix '{suf}' appended to full filename",
            confidence = 18,
            category   = "BACKUP",
            source_url = js.original_url,
        )


def mut_directory_variants(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: DIR
    Place the observed filename into alternate common asset directories.
    Useful when the application serves the same bundle from multiple paths,
    or when an asset moves between build configurations (dist/, build/, public/).
    Only generates when a plausible base URL (host) exists.
    """
    if not js.host:
        return
    if js.extension == ".js.map":
        return

    current_path = js.directory.lower()
    for alt_dir in ALT_ASSET_DIRS:
        if alt_dir.lower() in current_path:
            continue   # Same directory (or already captured)
        alt_dir_norm = "/" + alt_dir.strip("/") + "/"
        yield Candidate(
            url        = _url_in_dir(js, js.filename, alt_dir_norm),
            strategy   = "dir_variant",
            reason     = f"Alternate asset directory: '{alt_dir_norm}'",
            confidence = 30,
            category   = "DIR",
            source_url = js.original_url,
        )


def mut_separator_variants(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Strategy: SEPARATOR
    Try alternate separator characters for the file basename.
    Applications inconsistently use kebab-case, snake_case, or camelCase
    for their JS filenames — especially across different parts of a build.
    """
    if js.chunk_num is not None:
        return

    name = js.basename
    if not re.search(r"[-_]", name):
        return  # No separator to vary

    dec = ".chunk" if js.has_chunk else (".bundle" if js.has_bundle else "")
    ext = ".js"
    hash_part = (js.hash_sep + js.hash) if js.hash else ""

    variants_generated: Set[str] = {name}

    # kebab → snake and vice versa
    if "-" in name:
        alt = name.replace("-", "_")
        if alt not in variants_generated:
            variants_generated.add(alt)
            yield Candidate(
                url        = _url_in_dir(js, alt + hash_part + dec + ext),
                strategy   = "separator_variant",
                reason     = f"snake_case variant of '{name}'",
                confidence = 28,
                category   = "HASH",
                source_url = js.original_url,
            )

    if "_" in name:
        alt = name.replace("_", "-")
        if alt not in variants_generated:
            variants_generated.add(alt)
            yield Candidate(
                url        = _url_in_dir(js, alt + hash_part + dec + ext),
                strategy   = "separator_variant",
                reason     = f"kebab-case variant of '{name}'",
                confidence = 28,
                category   = "HASH",
                source_url = js.original_url,
            )


# ══════════════════════════════════════════════════════════════════════════════
#  MULTI-URL CONTEXT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def build_context(parsed_list: List[ParsedJS]) -> dict:
    """
    Analyse a collection of parsed URLs to extract cross-URL patterns.

    Returns a context dict consumed by mutation strategies:
      confirmed_hash      – hash shared by ≥2 files (strong signal it's a real build hash)
      confirmed_hash_sep  – separator used with the confirmed hash
      chunk_sequence      – sorted list of all numeric chunk IDs seen
      chunk_gaps          – missing integers within the observed chunk range
      known_basenames     – set of already-known semantic names
      framework           – most-voted framework across inputs
      build_system        – most-voted build system
    """
    ctx: dict = {
        "confirmed_hash":     None,
        "confirmed_hash_sep": ".",
        "chunk_sequence":     [],
        "chunk_gaps":         [],
        "known_basenames":    set(),
        "framework":          None,
        "build_system":       None,
    }

    hash_counter: Dict[str, int] = defaultdict(int)
    hash_sep_for: Dict[str, str] = {}
    fw_counter:   Dict[str, int] = defaultdict(int)
    bs_counter:   Dict[str, int] = defaultdict(int)
    chunk_nums:   List[int] = []

    for js in parsed_list:
        ctx["known_basenames"].add(js.basename)
        if js.hash:
            hash_counter[js.hash] += 1
            if js.hash_sep:
                hash_sep_for[js.hash] = js.hash_sep
        if js.framework:
            fw_counter[js.framework] += 1
        if js.build_system:
            bs_counter[js.build_system] += 1
        if js.chunk_num is not None:
            chunk_nums.append(js.chunk_num)

    # Confirmed hash: any hash seen in ≥2 files (or single file if only 1 input)
    if hash_counter:
        best_hash = max(hash_counter, key=lambda h: hash_counter[h])
        if hash_counter[best_hash] >= 1:
            ctx["confirmed_hash"]     = best_hash
            ctx["confirmed_hash_sep"] = hash_sep_for.get(best_hash, ".")

    # Framework / build system consensus
    if fw_counter:
        ctx["framework"] = max(fw_counter, key=fw_counter.__getitem__)
    if bs_counter:
        ctx["build_system"] = max(bs_counter, key=bs_counter.__getitem__)

    # Numeric chunk gap analysis
    if chunk_nums:
        ctx["chunk_sequence"] = sorted(set(chunk_nums))
        lo, hi = min(chunk_nums), max(chunk_nums)
        gaps = [i for i in range(lo, hi + 1) if i not in chunk_nums]
        ctx["chunk_gaps"] = gaps

    return ctx


# ══════════════════════════════════════════════════════════════════════════════
#  ORCHESTRATION
# ══════════════════════════════════════════════════════════════════════════════

# All mutation strategy functions, in priority order
_STRATEGIES = [
    mut_source_map,
    mut_hash_removal,
    mut_minified_toggle,
    mut_framework_companions,
    mut_webpack_infra,
    mut_adjacent_chunks,
    mut_sibling_bases,
    mut_route_siblings,
    mut_extension_variants,
    mut_env_variants,
    mut_separator_variants,
    mut_directory_variants,
    mut_backup_variants,
]


def generate_candidates(
    parsed_list: List[ParsedJS],
    min_score: int = 0,
    categories: Optional[Set[str]] = None,
) -> List[Candidate]:
    """
    Run all mutation strategies against all parsed URLs.
    Returns a deduplicated, sorted list of Candidates.
    """
    ctx        = build_context(parsed_list)
    input_urls = {j.original_url.rstrip("/") for j in parsed_list}

    def _process(js: ParsedJS) -> List[Candidate]:
        out = []
        for strategy_fn in _STRATEGIES:
            try:
                for cand in strategy_fn(js, ctx):
                    if cand.confidence < min_score:
                        continue
                    if categories and cand.category not in categories:
                        continue
                    out.append(cand)
            except Exception:
                pass  # Never crash on a single strategy failure
        return out

    workers = min(32, (os.cpu_count() or 4) * 2)
    seen:    set            = set()
    results: List[Candidate] = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for batch in ex.map(_process, parsed_list):
            for cand in batch:
                norm = cand.url.rstrip("/").lower()
                if norm in seen:
                    continue
                if cand.url.rstrip("/") in input_urls:
                    continue
                seen.add(norm)
                results.append(cand)

    # Sort: confidence descending, then category, then URL
    results.sort(key=lambda c: (-c.confidence, c.category, c.url))
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT FORMATTING
# ══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
     ___ _____   __           _            _
    |_  /  ___|  \ \  ____ _ | | ___ _ __ | |_
      | \__ \     \ \/ / _` || |/ _ \ '_ \| __|
  /\  | |__/ /    /  \ (_| || |  __/ | | | |_
  \___/\____/    /_/\_\__,_||_|\___|_| |_|\__|

  Smart JavaScript Asset Discovery Tool  v{version}
  Target-aware mutation · No blind wordlist expansion
""".format(version=TOOL_VERSION)

_CATEGORY_LABELS = {
    "SOURCE_MAP": "Source Maps",
    "HASH":       "Hash / Extension Variants",
    "COMPANION":  "Framework Companion Files",
    "CHUNK":      "Chunk Variants",
    "SIBLING":    "Sibling Bundles",
    "ROUTE":      "Route Siblings",
    "ENV":        "Environment Variants",
    "BACKUP":     "Backup / Legacy Files",
    "DIR":        "Directory Variants",
}

_CONF_COLOR = {
    range(80, 101): "\033[92m",   # bright green
    range(60, 80):  "\033[33m",   # yellow
    range(40, 60):  "\033[93m",   # dim yellow
    range(0, 40):   "\033[90m",   # grey
}


def _conf_color(score: int) -> str:
    for r, code in _CONF_COLOR.items():
        if score in r:
            return code
    return ""


def _fw_label(fw: Optional[str]) -> str:
    labels = {
        "nextjs": "Next.js",
        "cra":    "Create React App",
        "nuxt":   "Nuxt.js",
        "angular": "Angular",
        "vite":   "Vite",
    }
    return labels.get(fw or "", fw or "Unknown")


def print_grouped(candidates: List[Candidate], parsed_list: List[ParsedJS],
                  ctx: dict, no_color: bool = False) -> None:
    """Print candidates grouped by category with confidence scores."""
    reset = "" if no_color else "\033[0m"

    print(BANNER)

    # Summary header
    print(f"  Input    : {len(parsed_list)} URL(s)")
    if ctx.get("framework"):
        print(f"  Framework: {_fw_label(ctx['framework'])}", end="")
        if ctx.get("build_system"):
            print(f"  ({ctx['build_system']})", end="")
        print()
    if ctx.get("confirmed_hash"):
        print(f"  Hash     : {ctx['confirmed_hash']} "
              f"({len(ctx['confirmed_hash'])} chars, sep='{ctx['confirmed_hash_sep']}')")
    print(f"  Generated: {len(candidates)} candidates\n")

    # Group by category
    grouped: Dict[str, List[Candidate]] = defaultdict(list)
    for c in candidates:
        grouped[c.category].append(c)

    category_order = [
        "SOURCE_MAP", "HASH", "COMPANION", "CHUNK",
        "SIBLING", "ENV", "BACKUP", "DIR",
    ]

    for cat in category_order:
        if cat not in grouped:
            continue
        items = grouped[cat]
        label = _CATEGORY_LABELS.get(cat, cat)
        print(f"  {'─' * 60}")
        print(f"  {label}  [{len(items)} candidates]")
        print(f"  {'─' * 60}")

        for c in items:
            color  = "" if no_color else _conf_color(c.confidence)
            marker = f"[{c.confidence:3d}]"
            print(f"  {color}{marker}{reset}  {c.url}")
            print(f"         {c.reason}")
        print()


def print_plain(candidates: List[Candidate]) -> None:
    """Print only URLs, one per line (for piping to httpx / ffuf / curl)."""
    for c in candidates:
        print(c.url)


def print_json_output(candidates: List[Candidate], parsed_list: List[ParsedJS],
                      ctx: dict) -> None:
    """Print full JSON output."""
    output = {
        "meta": {
            "version":        TOOL_VERSION,
            "input_count":    len(parsed_list),
            "output_count":   len(candidates),
            "framework":      ctx.get("framework"),
            "build_system":   ctx.get("build_system"),
            "confirmed_hash": ctx.get("confirmed_hash"),
            "chunk_sequence": ctx.get("chunk_sequence", []),
            "chunk_gaps":     ctx.get("chunk_gaps", []),
        },
        "candidates": [c.to_dict() for c in candidates],
    }
    print(json.dumps(output, indent=2))


def save_results(candidates: List[Candidate], path: str, as_json: bool,
                 parsed_list: List[ParsedJS], ctx: dict) -> None:
    """Write results to a file."""
    if as_json:
        output = {
            "meta": {
                "version":        TOOL_VERSION,
                "input_count":    len(parsed_list),
                "output_count":   len(candidates),
                "framework":      ctx.get("framework"),
                "build_system":   ctx.get("build_system"),
                "confirmed_hash": ctx.get("confirmed_hash"),
                "chunk_sequence": ctx.get("chunk_sequence", []),
                "chunk_gaps":     ctx.get("chunk_gaps", []),
            },
            "candidates": [c.to_dict() for c in candidates],
        }
        with open(path, "w") as f:
            json.dump(output, f, indent=2)
    else:
        with open(path, "w") as f:
            for c in candidates:
                f.write(c.url + "\n")
    print(f"\n  Saved {len(candidates)} candidates to: {path}", file=sys.stderr)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog        = "jsreaper",
        description = "Smart JavaScript Asset Discovery — pattern-aware URL mutation",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent("""\
            examples:
              %(prog)s -u "https://app.example.com/static/js/main.a3f4b2c1.chunk.js"
              %(prog)s -f urls.txt --min-score 60 -o candidates.txt
              %(prog)s -f urls.txt --json -o results.json
              %(prog)s -f urls.txt --plain | httpx -silent -mc 200
              %(prog)s -f urls.txt --categories SOURCE_MAP,COMPANION
        """),
    )

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url",  metavar="URL",  help="Single JavaScript URL")
    src.add_argument("-f", "--file", metavar="FILE", help="File containing JS URLs (one per line)")

    ap.add_argument("-o", "--output",     metavar="FILE",
                    help="Save results to this file")
    ap.add_argument("--min-score",        metavar="N", type=int, default=0,
                    help="Only emit candidates with confidence ≥ N (default: 0)")
    ap.add_argument("--categories",       metavar="CAT[,CAT]",
                    help="Comma-separated list of categories to include "
                         "(SOURCE_MAP, HASH, COMPANION, CHUNK, SIBLING, ENV, BACKUP, DIR)")

    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--plain", action="store_true",
                     help="Output URLs only (pipe to httpx, curl, ffuf)")
    fmt.add_argument("--json",  action="store_true",
                     help="Output structured JSON")

    ap.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    return ap


def main() -> None:
    ap     = build_arg_parser()
    args   = ap.parse_args()

    # ── Collect raw URLs ──────────────────────────────────────────────────────
    raw_urls: List[str] = []

    if args.url:
        raw_urls = [args.url]
    else:
        try:
            with open(args.file) as f:
                raw_urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            ap.error(f"File not found: {args.file}")
        except OSError as e:
            ap.error(str(e))

    if not raw_urls:
        ap.error("No URLs provided.")

    # ── Parse ─────────────────────────────────────────────────────────────────
    parsed_list: List[ParsedJS] = []
    skipped = 0
    for raw in raw_urls:
        result = parse_js_url(raw)
        if result:
            parsed_list.append(result)
        else:
            skipped += 1

    if not parsed_list:
        print("[!] No valid JavaScript URLs found in input.", file=sys.stderr)
        if skipped:
            print(f"[!] Skipped {skipped} non-JS or unparseable entries.", file=sys.stderr)
        sys.exit(1)

    if skipped and not args.plain:
        print(f"[*] Skipped {skipped} non-JS entries.", file=sys.stderr)

    # ── Category filter ───────────────────────────────────────────────────────
    cat_filter: Optional[Set[str]] = None
    if args.categories:
        cat_filter = {c.strip().upper() for c in args.categories.split(",")}

    # ── Generate ──────────────────────────────────────────────────────────────
    candidates = generate_candidates(parsed_list, min_score=args.min_score,
                                     categories=cat_filter)
    ctx = build_context(parsed_list)   # rebuild for display (idempotent)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.plain:
        print_plain(candidates)
    elif args.json:
        print_json_output(candidates, parsed_list, ctx)
    else:
        print_grouped(candidates, parsed_list, ctx, no_color=args.no_color)

    # ── Save ──────────────────────────────────────────────────────────────────
    if args.output:
        save_results(candidates, args.output, as_json=args.json,
                     parsed_list=parsed_list, ctx=ctx)


if __name__ == "__main__":
    main()
