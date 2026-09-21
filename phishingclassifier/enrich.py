"""Threat intelligence enrichment using VirusTotal and urlscan.io."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
VT_BASE = "https://www.virustotal.com/api/v3"
VT_MIN_INTERVAL = 15.5
URLSCAN_BASE = "https://urlscan.io/api/v1"
# urlscan.io is a separate service from VirusTotal, so its lookups are not
# bound by VT's 4-requests-per-minute budget. We run them on a small bounded
# pool so their network I/O overlaps VT's mandatory cooldown instead of
# blocking inline.
URLSCAN_MAX_WORKERS = 5

# Threat intelligence goes stale: a domain that is clean today may be
# weaponized tomorrow. Cached verdicts expire after this many seconds so a
# returning analyst is not fed outdated signals. Override via the
# VT_CACHE_TTL env var (seconds; 0 disables caching entirely).
DEFAULT_CACHE_TTL = 24 * 3600

_CACHE_SUBDIR = "cache"
_CACHE_FILE = "vt_cache.json"


class EnrichmentState:
    """Tracks API keys, cache, and rate limiting."""

    def __init__(self, offline: bool = False, workdir: str = ".",
                 cache_ttl: Optional[int] = None) -> None:
        self.offline = offline
        self.cache_path = Path(workdir) / _CACHE_SUBDIR / _CACHE_FILE
        self.cache_ttl = self._resolve_ttl(cache_ttl)
        self.vt_key: Optional[str] = None
        self.urlscan_key: Optional[str] = None
        self._cache: Dict[str, Any] = {}
        self._last_vt_request = 0.0
        self._lock = threading.RLock()
        self.requests_made = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_expired = 0
        self.errors: List[str] = []
        self._load_keys(workdir)
        if self.vt_key or self.urlscan_key:
            self._load_cache()

    @staticmethod
    def _resolve_ttl(cache_ttl: Optional[int]) -> int:
        """Explicit arg wins, then VT_CACHE_TTL env, then the default."""
        raw = cache_ttl
        if raw is None:
            env = os.environ.get("VT_CACHE_TTL", "").strip()
            raw = int(env) if env.lstrip("+").isdigit() else DEFAULT_CACHE_TTL
        return max(0, int(raw))

    def _load_keys(self, workdir: str = ".") -> None:
        # .env lookup order: explicit workdir (tests pass tmp_path to
        # isolate), then repo root (so the CLI/dashboard find keys no
        # matter the cwd), then process cwd. First existing file wins;
        # real environment variables always take precedence.
        candidates = [
            Path(workdir) / ".env",
            Path(__file__).resolve().parent.parent / ".env",
            Path(".env"),
        ]
        for env_path in candidates:
            if not env_path.is_file():
                continue
            try:
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key, value = key.strip(), value.strip().strip('"').strip("'")
                    if key == "VT_API_KEY" and value:
                        self.vt_key = value
                    elif key == "URLSCAN_API_KEY" and value:
                        self.urlscan_key = value
            except OSError:
                pass
            break  # first existing .env wins; never stack multiple files

        # environment variables take precedence
        env_vt = os.environ.get("VT_API_KEY", "").strip()
        env_us = os.environ.get("URLSCAN_API_KEY", "").strip()
        if env_vt:
            self.vt_key = env_vt
        if env_us:
            self.urlscan_key = env_us
        if self.offline:
            self.vt_key = None
            self.urlscan_key = None

    @property
    def enabled(self) -> bool:
        return bool(self.vt_key or self.urlscan_key)

    def _load_cache(self) -> None:
        try:
            if self.cache_path.is_file():
                self._cache = json.loads(
                    self.cache_path.read_text(encoding="utf-8")
                )
        except (OSError, json.JSONDecodeError):
            # A corrupt/unreadable cache is recoverable (we start empty),
            # but silently discarding it can confuse an analyst -- log it.
            logger.warning("could not read VT cache %s; starting empty",
                           self.cache_path, exc_info=True)
            self._cache = {}
        # Drop stale (and legacy, untimed) entries so the cache file cannot
        # grow without bound and never serves outdated verdicts.
        if self._prune_expired():
            self._save_cache()

    def _is_stale(self, entry: Any) -> bool:
        """True when an entry is missing its envelope or has aged past TTL.

        Legacy entries written before TTL support lack the envelope and are
        treated as stale on purpose: better to refetch than trust a verdict
        we cannot date.
        """
        if not isinstance(entry, dict) or "at" not in entry \
                or "value" not in entry:
            return True
        if self.cache_ttl <= 0:
            return True
        return (time.time() - entry["at"]) > self.cache_ttl

    def _prune_expired(self) -> bool:
        """Remove stale entries; return True if anything was dropped."""
        dropped = [k for k, v in self._cache.items() if self._is_stale(v)]
        for k in dropped:
            self._cache.pop(k, None)
            self.cache_expired += 1
        return bool(dropped)

    def _save_cache(self) -> None:
        """Atomic write to cache file (caller holds the lock or init)."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                dir=str(self.cache_path.parent), suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self._cache, fh, indent=1)
                os.replace(tmp, str(self.cache_path))
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError as exc:
            self.errors.append(f"cache write failed: {exc}")

    def _cached(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.cache_misses += 1
                return None
            if self._is_stale(entry):
                self._cache.pop(key, None)
                self.cache_expired += 1
                self._save_cache()
                self.cache_misses += 1
                return None
            self.cache_hits += 1
            return entry["value"]

    def _put_cache(self, key: str, value: Dict[str, Any]) -> None:
        with self._lock:
            self._cache[key] = {"at": time.time(), "value": value}
            self._save_cache()

    def _http_get(self, url: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """GET request with timeouts and rate-limit backoff."""
        try:
            import requests
        except ImportError:
            self.errors.append("requests not installed -> offline mode")
            self.offline = True
            return None
        try:
            resp = requests.get(
                url, headers=headers,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            self.requests_made += 1
            if resp.status_code == 429:
                wait = min(
                    float(resp.headers.get("Retry-After", VT_MIN_INTERVAL)),
                    60.0,
                )
                time.sleep(max(wait, 0.0))
                resp = requests.get(
                    url, headers=headers,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                )
                self.requests_made += 1
            if resp.status_code != 200:
                self.errors.append(
                    f"HTTP {resp.status_code} for {url.split('?')[0]}"
                )
                return None
            return resp.json()
        except requests.RequestException as exc:
            self.errors.append(f"network error: {type(exc).__name__}")
            return None
        except ValueError:
            self.errors.append("invalid JSON response")
            return None

    def _vt_get(self, path: str) -> Optional[Dict[str, Any]]:
        if not self.vt_key:
            return None
        key = f"vt:{path}"
        cached = self._cached(key)
        if cached is not None:
            return cached
        elapsed = time.monotonic() - self._last_vt_request
        if elapsed < VT_MIN_INTERVAL:
            time.sleep(VT_MIN_INTERVAL - elapsed)
        self._last_vt_request = time.monotonic()
        data = self._http_get(
            f"{VT_BASE}{path}", {"X-Apikey": self.vt_key}
        )
        if data is not None:
            self._put_cache(key, data)
        return data

    def vt_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        data = self._vt_get(f"/ip_addresses/{ip}")
        return self._vt_summarize(data, prefix="ip") if data else None

    def vt_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        data = self._vt_get(f"/domains/{domain}")
        return self._vt_summarize(data, prefix="domain") if data else None

    def vt_file_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        data = self._vt_get(f"/files/{sha256}")
        return self._vt_summarize(data, prefix="file") if data else None

    def vt_url(self, url: str) -> Optional[Dict[str, Any]]:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = self._vt_get(f"/urls/{url_id}")
        return self._vt_summarize(data, prefix="url") if data else None

    @staticmethod
    def _vt_summarize(data: Dict[str, Any], prefix: str) -> Dict[str, Any]:
        attrs = (data.get("data") or {}).get("attributes") or {}
        last_analysis = attrs.get("last_analysis_stats") or {}
        return {
            "source": "virustotal",
            "type": prefix,
            "malicious": last_analysis.get("malicious", 0),
            "suspicious": last_analysis.get("suspicious", 0),
            "harmless": last_analysis.get("harmless", 0),
            "undetected": last_analysis.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
        }

    def urlscan_search(self, domain: str) -> Optional[Dict[str, Any]]:
        """Search existing urlscan.io scan results."""
        if not self.urlscan_key:
            return None
        key = f"urlscan:{domain}"
        cached = self._cached(key)
        if cached is not None:
            return cached
        try:
            import requests
        except ImportError:
            self.errors.append("requests not installed -> offline mode")
            self.offline = True
            return None
        try:
            resp = requests.get(
                f"{URLSCAN_BASE}/search/",
                params={"q": f"domain:{domain}", "size": 10},
                headers={"API-Key": self.urlscan_key},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            self.requests_made += 1
            if resp.status_code != 200:
                self.errors.append(f"urlscan HTTP {resp.status_code}")
                return None
            data = resp.json()
            total = data.get("total") or 0
            results = data.get("results") or []
            summary = {
                "source": "urlscan",
                "type": "domain_search",
                "total_existing_scans": total,
                "verdicts_seen": sorted({
                    (r.get("verdicts") or {}).get("overall", "")
                    for r in results if isinstance(r, dict)
                } - {""}),
            }
            self._put_cache(key, summary)
            return summary
        except requests.RequestException as exc:
            self.errors.append(f"urlscan network error: {type(exc).__name__}")
            return None
        except ValueError:
            self.errors.append("urlscan invalid JSON")
            return None


def enrich_result(result: Dict[str, Any], state: EnrichmentState,
                  max_lookups: int = 20) -> Dict[str, Any]:
    """Enrich IOCs for a single email result."""
    enrichment: Dict[str, Any] = {"mode": "offline", "lookups": [], "errors": []}
    if state.offline or not state.enabled:
        enrichment["mode"] = (
            "offline (--offline flag)" if state.offline else
            "offline (no API keys configured)"
        )
        return enrichment

    enrichment["mode"] = "live"

    # Phase 1: plan the exact set of lookups (identical budget accounting to
    # the original sequential code) so behavior is unchanged; only the
    # *timing* differs. Each slot is (kind, payload).
    plan: List[tuple] = []
    budget = max_lookups
    origin_ip = result.get("origin_ip")
    if origin_ip and budget > 0:
        plan.append(("vt_ip", origin_ip))
        budget -= 1

    iocs = result.get("iocs") or {}
    domains = (iocs.get("domains", {}).get("header", [])
               + iocs.get("domains", {}).get("body", []))
    for domain in dict.fromkeys(domains):
        if budget <= 0:
            break
        plan.append(("vt_domain", domain))
        budget -= 1
        if state.urlscan_key and budget > 0:
            plan.append(("urlscan", domain))
            budget -= 1

    for att in iocs.get("attachment_hashes", []):
        if budget <= 0:
            break
        plan.append(("vt_hash", att))
        budget -= 1

    # Phase 2: execute. VirusTotal is rate-limited to ~4 req/min, so its
    # lookups stay sequential on this thread. urlscan.io is a separate
    # service, so we fire all its searches on a small pool first; their
    # network I/O overlaps the VT cooldown instead of blocking inline.
    slot_result: Dict[int, Optional[Dict[str, Any]]] = {}
    futures: Dict[int, Future] = {}
    pool: Optional[ThreadPoolExecutor] = None
    try:
        urlscan_slots = [i for i, (k, _) in enumerate(plan) if k == "urlscan"]
        if urlscan_slots:
            pool = ThreadPoolExecutor(max_workers=URLSCAN_MAX_WORKERS)
            for i in urlscan_slots:
                futures[i] = pool.submit(state.urlscan_search, plan[i][1])

        for i, (kind, payload) in enumerate(plan):
            if kind == "vt_ip":
                slot_result[i] = state.vt_ip(payload)
            elif kind == "vt_domain":
                slot_result[i] = state.vt_domain(payload)
            elif kind == "vt_hash":
                slot_result[i] = state.vt_file_hash(payload.get("sha256", ""))

        for i, fut in futures.items():
            try:
                slot_result[i] = fut.result()
            except Exception as exc:
                state.errors.append(
                    f"urlscan lookup failed: {type(exc).__name__}")
                slot_result[i] = None
    except Exception as exc:
        enrichment["errors"].append(f"enrichment failure: {type(exc).__name__}")
    finally:
        if pool is not None:
            pool.shutdown(wait=False)

    # Phase 3: assemble in plan order so output matches the sequential run.
    for i, (kind, payload) in enumerate(plan):
        summary = slot_result.get(i)
        if not summary:
            continue
        if kind == "vt_hash":
            enrichment["lookups"].append(
                {"ioc": payload.get("filename", ""), **summary})
        else:
            enrichment["lookups"].append({"ioc": payload, **summary})

    enrichment["errors"].extend(state.errors[-5:])
    return enrichment
