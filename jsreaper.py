#!/usr/bin/env python3
"""
jsreaper.py  —  Smart JavaScript Asset Discovery
=================================================
v2.0.0

Takes JavaScript URLs discovered during recon and generates hidden asset
candidates using pattern-aware mutation. Every candidate is derived from
structure observed in the target — hash, separator, chunk convention,
framework fingerprint — not a blind wordlist.

Usage
─────
  python jsreaper.py -u "https://app.example.com/static/js/main.a3f4b2c1.chunk.js"
  python jsreaper.py -f urls.txt
  python jsreaper.py -f urls.txt --plain | httpx -silent -mc 200
  python jsreaper.py -f urls.txt --json -o results.json
  python jsreaper.py -f urls.txt --categories SOURCE_MAP,SENSITIVE
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
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse
from pathlib import PurePosixPath


TOOL_VERSION = "2.0.0"

# ── Vocabulary constants ───────────────────────────────────────────────────────

# Common route / feature names found in lazy-loaded chunks
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

# Generic sibling bundle names expected alongside the main bundle
SIBLING_BASES: List[str] = [
    "main", "app", "index",
    "vendor", "vendors",
    "runtime", "runtime-main",
    "polyfills",
    "bootstrap", "common", "commons",
    "shared", "core", "lib",
    "utils", "init", "entry",
    "framework", "scripts", "bundle", "chunk",
]

# Webpack infrastructure bundle names
WEBPACK_INFRA: List[str] = [
    "webpack-runtime", "webpack", "webpack-bundle",
    "vendors~main", "vendors~app", "vendors~async",
    "vendors", "vendor",
    "runtime-main", "runtime",
    "commons", "common",
    "polyfills",
]

# Framework-specific companion files: path_fragment → [filenames]
FRAMEWORK_COMPANIONS: Dict[str, Dict[str, List[str]]] = {
    "nextjs": {
        "_next/static/chunks": [
            "webpack.js", "main.js", "polyfills.js", "framework.js", "commons.js",
        ],
        "_next/static/chunks/pages": [
            "_app.js", "_error.js", "_document.js", "index.js", "404.js",
        ],
    },
    "nuxt": {
        "_nuxt": [
            "app.js", "vendor.js", "manifest.js",
            "runtime.js", "commons.app.js", "index.js",
        ],
    },
    "cra": {
        "static/js": [
            "main.chunk.js", "runtime-main.js",
            "0.chunk.js", "1.chunk.js", "2.chunk.js",
            "vendors~main.chunk.js",
        ],
    },
    "angular": {
        "": [
            "main.js", "polyfills.js", "runtime.js",
            "vendor.js", "styles.js", "common.js",
        ],
    },
    "vite": {
        "assets": ["index.js", "vendor.js"],
    },
}

# Sensitive functionality keywords — applied to the target's observed naming pattern
# to surface hidden JS bundles for privileged or security-relevant features.
SENSITIVE_WORDS: List[str] = [
    # Financial
    "payment", "payments", "billing", "checkout", "invoice", "invoices",
    "transaction", "transactions", "wallet", "subscription", "subscriptions",
    "refund", "payout", "payouts", "pricing", "coupon", "discount",
    # Admin / internal panels
    "admin", "administrator", "internal", "backoffice", "back-office",
    "management", "staff", "operator", "superuser", "panel", "console",
    "impersonate", "masquerade", "override",
    # Auth / identity
    "auth", "authentication", "authorization", "oauth", "sso", "mfa",
    "2fa", "token", "session", "jwt", "saml", "passkey", "recovery",
    # API / integrations
    "api", "graphql", "webhook", "webhooks", "integration", "integrations",
    "connector", "sync", "bridge",
    # Data / export
    "export", "import", "upload", "download", "report", "reports",
    "audit", "logs", "logger", "telemetry", "gdpr", "data-export",
    # User / access management
    "users", "accounts", "permissions", "roles", "acl", "rbac",
    "invite", "invitation",
    # Config / feature control
    "config", "configuration", "feature-flags", "flags",
    "secrets", "keys", "credentials",
    # Sensitive operations
    "debug", "diagnostics", "migrate", "migration", "seed",
    "delete", "bulk", "purge", "reset", "restore",
    # Enterprise
    "enterprise", "license", "compliance",
]

# Tokens that look hash-like but must never be treated as content hashes.
# Built from reserved keywords + all vocabulary wordlists.
_NOT_HASH: Set[str] = {
    "min", "dev", "prod", "app", "lib", "js", "css",
    "src", "map", "chunk", "bundle", "runtime", "vendor",
    "main", "index", "common", "async", "lazy", "core",
    "utils", "polyfills", "bootstrap", "worker", "sw",
    "service", "module", "es5", "es6", "es2015", "es2020",
    "umd", "cjs", "esm", "ssr", "client", "server", "legacy",
    "test", "spec", "staging", "local", "next",
    "nuxt", "react", "angular", "vue", "svelte",
    "production", "development",
    "not", "found",
}
_NOT_HASH.update(w.lower().replace("-", "").replace("_", "") for w in ROUTE_NAMES)
_NOT_HASH.update(w.lower().replace("-", "").replace("_", "") for w in SIBLING_BASES)
_NOT_HASH.update(w.lower().replace("-", "").replace("_", "") for w in SENSITIVE_WORDS)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class ParsedJS:
    original_url: str
    scheme:       str
    host:         str
    path:         str
    directory:    str
    filename:     str
    stem:         str
    extension:    str          # ".js" or ".js.map"
    basename:     str          # stem stripped of hash and decorators
    hash_val:     Optional[str]
    hash_sep:     Optional[str]  # "." or "-"
    chunk_num:    Optional[int]  # set if basename is a pure integer
    has_chunk:    bool
    is_minified:  bool
    is_lazy:      bool
    lazy_target:  Optional[str]
    framework:    Optional[str]
    build_system: Optional[str]


@dataclass
class Candidate:
    url:        str
    strategy:   str
    category:   str
    reason:     str
    source_url: str


# ── URL parsing ────────────────────────────────────────────────────────────────

def _is_hash(token: str) -> bool:
    """Return True if the token looks like a content hash."""
    if not token:
        return False
    t = token.lower().replace("-", "").replace("_", "")
    if t in _NOT_HASH:
        return False
    n = len(token)
    # Pure hex: 6–32 chars
    if re.fullmatch(r"[a-f0-9]+", token) and 6 <= n <= 32:
        return True
    # Alphanumeric: 8–16 chars
    if re.fullmatch(r"[a-z0-9]+", token, re.I) and 8 <= n <= 16:
        return True
    return False


def _detect_framework(path: str, filename: str) -> Tuple[Optional[str], Optional[str]]:
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
    """Parse a raw URL string into a ParsedJS. Returns None for non-JS input."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    elif raw.startswith("./"):
        raw = "https://relative" + raw[1:]
    elif raw.startswith("/"):
        raw = "https://relative" + raw

    try:
        parsed = urlparse(raw)
    except Exception:
        return None

    path = parsed.path
    if not path:
        return None

    filename = PurePosixPath(path).name
    if not filename:
        return None

    fl = filename.lower()
    if fl.endswith(".js.map"):
        extension, stem = ".js.map", filename[:-7]
    elif fl.endswith(".js"):
        extension, stem = ".js", filename[:-3]
    else:
        return None

    directory = str(PurePosixPath(path).parent)
    if directory == ".":
        directory = "/"

    framework, build_system = _detect_framework(path, filename)

    has_chunk   = ".chunk" in stem.lower()
    is_minified = ".min"   in stem.lower()

    # Strip decorators to get the hashable stem
    clean = re.sub(r"\.chunk$", "", stem, flags=re.I)
    clean = re.sub(r"\.min$",   "", clean, flags=re.I)

    hash_val, hash_sep, basename = None, None, clean
    for sep in (".", "-"):
        parts = clean.rsplit(sep, 1)
        if len(parts) == 2 and _is_hash(parts[1]):
            hash_val, hash_sep, basename = parts[1], sep, parts[0]
            break

    chunk_num: Optional[int] = None
    try:
        chunk_num = int(basename)
    except ValueError:
        pass

    is_lazy     = bool(re.match(r"lazy[-_]", basename, re.I))
    lazy_target = re.sub(r"^lazy[-_]", "", basename, flags=re.I) if is_lazy else None

    scheme = parsed.scheme if parsed.scheme not in ("", "relative") else "https"
    host   = parsed.netloc if parsed.netloc != "relative" else ""

    return ParsedJS(
        original_url = raw,
        scheme       = scheme,
        host         = host,
        path         = path,
        directory    = directory,
        filename     = filename,
        stem         = stem,
        extension    = extension,
        basename     = basename,
        hash_val     = hash_val,
        hash_sep     = hash_sep,
        chunk_num    = chunk_num,
        has_chunk    = has_chunk,
        is_minified  = is_minified,
        is_lazy      = is_lazy,
        lazy_target  = lazy_target,
        framework    = framework,
        build_system = build_system,
    )


def _url_in_dir(js: ParsedJS, new_filename: str) -> str:
    new_path = str(PurePosixPath(js.directory) / new_filename)
    if js.host:
        return f"{js.scheme}://{js.host}{new_path}"
    return new_path


# ── Context building ───────────────────────────────────────────────────────────

def build_context(parsed_list: List[ParsedJS]) -> dict:
    """
    Cross-URL analysis across the full input set.
    Confirms the shared build hash, detects chunk sequence gaps,
    and votes on framework / build system.
    """
    hash_count:   Dict[str, int]  = defaultdict(int)
    hash_sep_for: Dict[str, str]  = {}
    chunk_nums:   List[int]       = []
    fw_votes:     Dict[str, int]  = defaultdict(int)
    bs_votes:     Dict[str, int]  = defaultdict(int)
    known:        Set[str]        = set()

    for js in parsed_list:
        known.add(js.basename.lower())
        if js.hash_val:
            hash_count[js.hash_val] += 1
            if js.hash_sep:
                hash_sep_for[js.hash_val] = js.hash_sep
        if js.chunk_num is not None:
            chunk_nums.append(js.chunk_num)
        if js.framework:
            fw_votes[js.framework] += 1
        if js.build_system:
            bs_votes[js.build_system] += 1

    ctx: dict = {"known_basenames": known}

    if hash_count:
        best = max(hash_count, key=hash_count.__getitem__)
        if hash_count[best] >= 2:
            ctx["confirmed_hash"]     = best
            ctx["confirmed_hash_sep"] = hash_sep_for.get(best, ".")

    if fw_votes:
        ctx["framework"] = max(fw_votes, key=fw_votes.__getitem__)
    if bs_votes:
        ctx["build_system"] = max(bs_votes, key=bs_votes.__getitem__)

    if chunk_nums:
        nums = set(chunk_nums)
        lo, hi = min(nums), max(nums)
        ctx["chunk_gaps"] = [i for i in range(lo, hi + 1) if i not in nums]

    return ctx


# ── Mutation strategies ────────────────────────────────────────────────────────

def mut_source_map(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """Append .map — source maps expose original source code, paths, and comments."""
    if js.extension == ".js.map":
        return
    yield Candidate(
        url        = _url_in_dir(js, js.filename + ".map"),
        strategy   = "source_map",
        category   = "SOURCE_MAP",
        reason     = f"Source map: {js.filename}.map",
        source_url = js.original_url,
    )
    if js.has_chunk:
        # Also try without .chunk decorator
        alt = js.basename + ((js.hash_sep + js.hash_val) if js.hash_val else "") + ".js.map"
        yield Candidate(
            url        = _url_in_dir(js, alt),
            strategy   = "source_map",
            category   = "SOURCE_MAP",
            reason     = f"Source map without .chunk: {alt}",
            source_url = js.original_url,
        )


def mut_hash_removal(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """Strip the content hash — CDNs often serve both hashed and unhashed paths."""
    if not js.hash_val:
        return
    dec = ".chunk" if js.has_chunk else ""

    yield Candidate(
        url        = _url_in_dir(js, js.basename + dec + ".js"),
        strategy   = "hash_removal",
        category   = "HASH",
        reason     = f"Unhashed: {js.basename + dec}.js",
        source_url = js.original_url,
    )
    if js.has_chunk:
        yield Candidate(
            url        = _url_in_dir(js, js.basename + ".js"),
            strategy   = "hash_removal",
            category   = "HASH",
            reason     = f"Bare unhashed: {js.basename}.js",
            source_url = js.original_url,
        )


def mut_minified_toggle(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """Toggle .min — unminified builds expose logic, comments, and variable names."""
    if js.extension == ".js.map":
        return
    hp  = (js.hash_sep + js.hash_val) if js.hash_val else ""
    dec = ".chunk" if js.has_chunk else ""

    if js.is_minified:
        yield Candidate(
            url        = _url_in_dir(js, js.basename + hp + dec + ".js"),
            strategy   = "minified_toggle",
            category   = "HASH",
            reason     = f"Non-minified counterpart: {js.basename + hp + dec}.js",
            source_url = js.original_url,
        )
    else:
        yield Candidate(
            url        = _url_in_dir(js, js.basename + hp + ".min" + dec + ".js"),
            strategy   = "minified_toggle",
            category   = "HASH",
            reason     = f"Minified counterpart: {js.basename + hp}.min{dec}.js",
            source_url = js.original_url,
        )


def mut_framework_companions(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """Generate framework-specific companion files (Next.js, Nuxt, CRA, Angular, Vite)."""
    fw = js.framework or ctx.get("framework")
    if not fw or fw not in FRAMEWORK_COMPANIONS:
        return
    for path_frag, filenames in FRAMEWORK_COMPANIONS[fw].items():
        if path_frag and path_frag.lower() not in js.path.lower():
            continue
        for fname in filenames:
            if fname.lower() == js.filename.lower():
                continue
            yield Candidate(
                url        = _url_in_dir(js, fname),
                strategy   = "framework_companion",
                category   = "COMPANION",
                reason     = f"{fw} companion: {fname}",
                source_url = js.original_url,
            )


def mut_webpack_infra(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """Generate Webpack infrastructure bundles using the confirmed build hash."""
    if ctx.get("build_system") != "webpack" and js.build_system != "webpack":
        return
    h     = ctx.get("confirmed_hash")
    sep   = ctx.get("confirmed_hash_sep") or js.hash_sep or "."
    known = ctx.get("known_basenames", set())

    for infra in WEBPACK_INFRA:
        if infra.lower() in known:
            continue
        if h:
            yield Candidate(
                url        = _url_in_dir(js, infra + sep + h + ".chunk.js"),
                strategy   = "webpack_infra",
                category   = "COMPANION",
                reason     = f"Webpack infra: {infra}",
                source_url = js.original_url,
            )
            yield Candidate(
                url        = _url_in_dir(js, infra + sep + h + ".js"),
                strategy   = "webpack_infra",
                category   = "COMPANION",
                reason     = f"Webpack infra: {infra}",
                source_url = js.original_url,
            )
        else:
            yield Candidate(
                url        = _url_in_dir(js, infra + ".js"),
                strategy   = "webpack_infra",
                category   = "COMPANION",
                reason     = f"Webpack infra: {infra}",
                source_url = js.original_url,
            )


def mut_adjacent_chunks(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Generate adjacent numeric chunk IDs and fill confirmed gaps in the sequence.
    Gap chunks are derived from cross-URL analysis and are the most reliable.
    """
    if js.chunk_num is None:
        return
    num = js.chunk_num
    h   = ctx.get("confirmed_hash") or js.hash_val
    sep = ctx.get("confirmed_hash_sep") or js.hash_sep or "."
    dec = ".chunk" if js.has_chunk else ""
    ext = js.extension

    gap_set = set(ctx.get("chunk_gaps", []))

    # Gap chunks first — confirmed missing from the observed sequence
    for gap in sorted(gap_set):
        if gap == num:
            continue
        name = str(gap) + (sep + h if h else "") + dec + ext
        yield Candidate(
            url        = _url_in_dir(js, name),
            strategy   = "chunk_gap",
            category   = "CHUNK",
            reason     = f"Gap chunk #{gap} — absent from observed sequence",
            source_url = js.original_url,
        )

    # Adjacent ±5 neighbors
    for delta in range(-5, 6):
        if delta == 0:
            continue
        neighbor = num + delta
        if neighbor < 0 or neighbor in gap_set:
            continue
        if h:
            yield Candidate(
                url        = _url_in_dir(js, str(neighbor) + sep + h + dec + ext),
                strategy   = "adjacent_chunk",
                category   = "CHUNK",
                reason     = f"Adjacent chunk #{neighbor} to #{num}",
                source_url = js.original_url,
            )
        yield Candidate(
            url        = _url_in_dir(js, str(neighbor) + dec + ext),
            strategy   = "adjacent_chunk",
            category   = "CHUNK",
            reason     = f"Adjacent chunk #{neighbor} to #{num} (no hash)",
            source_url = js.original_url,
        )


def mut_sibling_bases(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Generate common sibling bundle names in the same directory, applying
    the confirmed build hash and chunk convention.
    """
    if js.chunk_num is not None:
        return
    h     = ctx.get("confirmed_hash")
    sep   = ctx.get("confirmed_hash_sep") or js.hash_sep or "."
    dec   = ".chunk" if js.has_chunk else ""
    known = ctx.get("known_basenames", set())

    for sibling in SIBLING_BASES:
        if sibling == js.basename or sibling.lower() in known:
            continue
        if h:
            yield Candidate(
                url        = _url_in_dir(js, sibling + sep + h + dec + ".js"),
                strategy   = "sibling_hashed",
                category   = "SIBLING",
                reason     = f"Sibling bundle: {sibling}",
                source_url = js.original_url,
            )
        yield Candidate(
            url        = _url_in_dir(js, sibling + dec + ".js"),
            strategy   = "sibling_plain",
            category   = "SIBLING",
            reason     = f"Sibling bundle: {sibling}",
            source_url = js.original_url,
        )
        if dec:
            yield Candidate(
                url        = _url_in_dir(js, sibling + ".js"),
                strategy   = "sibling_plain",
                category   = "SIBLING",
                reason     = f"Sibling bundle: {sibling}",
                source_url = js.original_url,
            )


def mut_route_siblings(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    When a lazy/route chunk is found, generate sibling routes.
    Reveals undocumented application sections and hidden functionality.
    """
    if js.chunk_num is not None:
        return
    if not js.is_lazy and js.basename.lower() not in ROUTE_NAMES:
        return

    target = js.lazy_target or js.basename
    h      = ctx.get("confirmed_hash")
    sep    = ctx.get("confirmed_hash_sep") or js.hash_sep or "."
    dec    = ".chunk" if js.has_chunk else ""
    known  = ctx.get("known_basenames", set())

    lazy_prefix = ("lazy" + js.basename[4]) if js.is_lazy and len(js.basename) > 4 else None

    for route in ROUTE_NAMES:
        if route == target or route.lower() in known:
            continue
        base = (lazy_prefix + route) if lazy_prefix else route
        if h:
            yield Candidate(
                url        = _url_in_dir(js, base + sep + h + dec + ".js"),
                strategy   = "route_sibling",
                category   = "SIBLING",
                reason     = f"Route sibling: {route} (pattern from {js.basename})",
                source_url = js.original_url,
            )
        yield Candidate(
            url        = _url_in_dir(js, base + dec + ".js"),
            strategy   = "route_sibling",
            category   = "SIBLING",
            reason     = f"Route sibling: {route}",
            source_url = js.original_url,
        )


def mut_sensitive_probes(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """
    Apply the target's observed JS naming pattern to a curated list of
    sensitive functionality keywords — payments, admin, auth, export, etc.
    Surfaces hidden bundles that serve privileged features but are not
    linked from the public application.
    """
    if js.chunk_num is not None:
        return
    h     = ctx.get("confirmed_hash")
    sep   = ctx.get("confirmed_hash_sep") or js.hash_sep or "."
    dec   = ".chunk" if js.has_chunk else ""
    known = ctx.get("known_basenames", set())

    lazy_prefix = ("lazy" + js.basename[4]) if js.is_lazy and len(js.basename) > 4 else None

    for word in SENSITIVE_WORDS:
        if word.lower() in known:
            continue

        # Lazy-prefixed variant — only when source is itself lazy-loaded
        if lazy_prefix:
            base = lazy_prefix + word
            if h:
                yield Candidate(
                    url        = _url_in_dir(js, base + sep + h + dec + ".js"),
                    strategy   = "sensitive_probe",
                    category   = "SENSITIVE",
                    reason     = f"Sensitive lazy bundle: {word}",
                    source_url = js.original_url,
                )
            yield Candidate(
                url        = _url_in_dir(js, base + dec + ".js"),
                strategy   = "sensitive_probe",
                category   = "SENSITIVE",
                reason     = f"Sensitive lazy bundle: {word} (no hash)",
                source_url = js.original_url,
            )

        # Named chunk with confirmed build hash
        if h:
            yield Candidate(
                url        = _url_in_dir(js, word + sep + h + dec + ".js"),
                strategy   = "sensitive_probe",
                category   = "SENSITIVE",
                reason     = f"Sensitive bundle: {word} (target hash applied)",
                source_url = js.original_url,
            )

        # Plain variants
        if dec:
            yield Candidate(
                url        = _url_in_dir(js, word + dec + ".js"),
                strategy   = "sensitive_probe",
                category   = "SENSITIVE",
                reason     = f"Sensitive bundle: {word}",
                source_url = js.original_url,
            )
        yield Candidate(
            url        = _url_in_dir(js, word + ".js"),
            strategy   = "sensitive_probe",
            category   = "SENSITIVE",
            reason     = f"Sensitive bundle: {word}",
            source_url = js.original_url,
        )


def mut_extension_variants(js: ParsedJS, ctx: dict) -> Iterator[Candidate]:
    """Toggle the .chunk decorator — some bundlers serve files both ways."""
    if js.extension == ".js.map" or js.chunk_num is not None:
        return
    hp = (js.hash_sep + js.hash_val) if js.hash_val else ""
    if js.has_chunk:
        yield Candidate(
            url        = _url_in_dir(js, js.basename + hp + ".js"),
            strategy   = "extension_variant",
            category   = "HASH",
            reason     = f"Variant without .chunk: {js.basename + hp}.js",
            source_url = js.original_url,
        )
    else:
        yield Candidate(
            url        = _url_in_dir(js, js.basename + hp + ".chunk.js"),
            strategy   = "extension_variant",
            category   = "HASH",
            reason     = f"Chunk variant: {js.basename + hp}.chunk.js",
            source_url = js.original_url,
        )


# ── Orchestration ──────────────────────────────────────────────────────────────

_STRATEGIES = [
    mut_source_map,
    mut_hash_removal,
    mut_minified_toggle,
    mut_framework_companions,
    mut_webpack_infra,
    mut_adjacent_chunks,
    mut_sibling_bases,
    mut_route_siblings,
    mut_sensitive_probes,
    mut_extension_variants,
]

_CATEGORY_ORDER = ["SOURCE_MAP", "SENSITIVE", "COMPANION", "HASH", "SIBLING", "CHUNK"]


def generate_candidates(
    parsed_list: List[ParsedJS],
    categories: Optional[Set[str]] = None,
) -> List[Candidate]:
    ctx        = build_context(parsed_list)
    input_urls = {j.original_url.rstrip("/") for j in parsed_list}

    def _process(js: ParsedJS) -> List[Candidate]:
        out = []
        for fn in _STRATEGIES:
            try:
                for cand in fn(js, ctx):
                    if categories and cand.category not in categories:
                        continue
                    out.append(cand)
            except Exception:
                pass
        return out

    workers = min(32, (os.cpu_count() or 4) * 2)
    seen:    Set[str]        = set()
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

    rank = {c: i for i, c in enumerate(_CATEGORY_ORDER)}
    results.sort(key=lambda c: (rank.get(c.category, 99), c.url))
    return results


# ── Output ─────────────────────────────────────────────────────────────────────

_ANSI = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[31m",
    "green":   "\033[32m",
    "yellow":  "\033[33m",
    "blue":    "\033[34m",
    "magenta": "\033[35m",
    "cyan":    "\033[36m",
    "white":   "\033[37m",
}

_CAT_COLOR = {
    "SOURCE_MAP": "red",
    "SENSITIVE":  "magenta",
    "COMPANION":  "yellow",
    "HASH":       "cyan",
    "SIBLING":    "green",
    "CHUNK":      "blue",
}

BANNER = r"""
     ___ ___ ___
    |_  / __| _ \ ___  __ _ _ __  ___ _ _
      | \__ \   // -_)/ _` | '_ \/ -_) '_|
  /\  | |___/_|_\\___|\_,_| .__/ \___|_|
  \___/                    |_|
  Smart JavaScript Asset Discovery  v{version}
  Pattern-aware mutation · No blind wordlists
"""


def _c(text: str, key: str, no_color: bool) -> str:
    if no_color:
        return text
    return _ANSI.get(key, "") + text + _ANSI["reset"]


def print_plain(candidates: List[Candidate]) -> None:
    for c in candidates:
        print(c.url)


def print_grouped(
    candidates: List[Candidate],
    parsed_list: List[ParsedJS],
    ctx: dict,
    no_color: bool = False,
) -> None:
    print(_c(BANNER.format(version=TOOL_VERSION), "bold", no_color))

    h = ctx.get("confirmed_hash", "—")
    fw = ctx.get("framework") or ctx.get("build_system") or "—"
    print(f"  Input    : {len(parsed_list)} URL(s)")
    print(f"  Hash     : {h}")
    print(f"  Framework: {fw}")
    print(f"  Generated: {len(candidates)} candidates")
    print()

    by_cat: Dict[str, List[Candidate]] = defaultdict(list)
    for c in candidates:
        by_cat[c.category].append(c)

    sep = _c("  " + "─" * 62, "dim", no_color)
    for cat in _CATEGORY_ORDER:
        items = by_cat.get(cat, [])
        if not items:
            continue
        color  = _CAT_COLOR.get(cat, "white")
        header = f"  {cat}  [{len(items)}]"
        print(sep)
        print(_c(header, color, no_color))
        print(sep)
        for item in items:
            print(f"  {item.url}")
        print()


def print_json_output(
    candidates: List[Candidate],
    parsed_list: List[ParsedJS],
    ctx: dict,
) -> None:
    output = {
        "meta": {
            "version":        TOOL_VERSION,
            "input_count":    len(parsed_list),
            "confirmed_hash": ctx.get("confirmed_hash"),
            "framework":      ctx.get("framework"),
            "build_system":   ctx.get("build_system"),
            "total":          len(candidates),
        },
        "candidates": [
            {
                "url":        c.url,
                "category":   c.category,
                "strategy":   c.strategy,
                "reason":     c.reason,
                "source_url": c.source_url,
            }
            for c in candidates
        ],
    }
    print(json.dumps(output, indent=2))


def save_results(
    candidates: List[Candidate],
    path: str,
    as_json: bool,
    parsed_list: List[ParsedJS],
    ctx: dict,
) -> None:
    if as_json:
        data = {
            "meta": {
                "version":        TOOL_VERSION,
                "input_count":    len(parsed_list),
                "confirmed_hash": ctx.get("confirmed_hash"),
                "total":          len(candidates),
            },
            "candidates": [
                {"url": c.url, "category": c.category,
                 "strategy": c.strategy, "reason": c.reason}
                for c in candidates
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    else:
        with open(path, "w") as f:
            for c in candidates:
                f.write(c.url + "\n")
    print(f"\n  Saved {len(candidates)} candidates to: {path}", file=sys.stderr)


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog        = "jsreaper",
        description = "Smart JavaScript Asset Discovery — pattern-aware URL mutation",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent("""\
            examples:
              %(prog)s -u "https://app.example.com/static/js/main.a3f4b2c1.chunk.js"
              %(prog)s -f urls.txt
              %(prog)s -f urls.txt --plain | httpx -silent -mc 200
              %(prog)s -f urls.txt --json -o results.json
              %(prog)s -f urls.txt --categories SOURCE_MAP,SENSITIVE
              %(prog)s -f urls.txt --categories CHUNK --plain | ffuf -u FUZZ -w -
        """),
    )

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url",  metavar="URL",  help="Single JavaScript URL")
    src.add_argument("-f", "--file", metavar="FILE", help="File of JS URLs (one per line)")

    ap.add_argument("-o", "--output",    metavar="FILE", help="Save results to file")
    ap.add_argument("--categories",      metavar="CAT[,CAT]",
                    help="Filter output: SOURCE_MAP, SENSITIVE, COMPANION, HASH, SIBLING, CHUNK")

    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--plain", action="store_true",
                     help="Output URLs only — pipe to httpx, ffuf, etc.")
    fmt.add_argument("--json",  action="store_true",
                     help="Structured JSON output")

    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return ap


def main() -> None:
    ap   = build_arg_parser()
    args = ap.parse_args()

    # Collect raw URLs
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

    # Parse
    parsed_list: List[ParsedJS] = []
    skipped = 0
    for raw in raw_urls:
        r = parse_js_url(raw)
        if r:
            parsed_list.append(r)
        else:
            skipped += 1

    if not parsed_list:
        print("[!] No valid JavaScript URLs found.", file=sys.stderr)
        sys.exit(1)

    if skipped and not args.plain:
        print(f"[*] Skipped {skipped} non-JS entries.", file=sys.stderr)

    # Category filter
    cat_filter: Optional[Set[str]] = None
    if args.categories:
        cat_filter = {c.strip().upper() for c in args.categories.split(",")}

    # Generate
    candidates = generate_candidates(parsed_list, categories=cat_filter)
    ctx        = build_context(parsed_list)

    # Output
    if args.plain:
        print_plain(candidates)
    elif args.json:
        print_json_output(candidates, parsed_list, ctx)
    else:
        print_grouped(candidates, parsed_list, ctx, no_color=args.no_color)

    # Save
    if args.output:
        save_results(candidates, args.output, as_json=args.json,
                     parsed_list=parsed_list, ctx=ctx)


if __name__ == "__main__":
    main()
