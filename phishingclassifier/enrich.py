"""Threat intelligence enrichment using VirusTotal and urlscan.io."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
VT_BASE = "https://www.virustotal.com/api/v3"
VT_MIN_INTERVAL = 15.5
URLSCAN_BASE = "https://urlscan.io/api/v1"

_CACHE_SUBDIR = "cache"
_CACHE_FILE = "vt_cache.json"


class EnrichmentState:
    """Tracks API keys, cache, and rate limiting."""

    def __init__(self, offline: bool = False, workdir: str = ".") -> None:
        self.offline = offline
        self.cache_path = Path(workdir) / _CACHE_SUBDIR / _CACHE_FILE
        self.vt_key: Optional[str] = None
        self.urlscan_key: Optional[str] = None
        self._cache: Dict[str, Any] = {}
        self._last_vt_request = 0.0
        self.requests_made = 0
        self.errors: List[str] = []
        self._load_keys()
        if self.vt_key or self.urlscan_key:
            self._load_cache()

    def _load_keys(self) -> None:
        # load from .env file if present
        env_path = Path(".env")
        if env_path.is_file():
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
            self._cache = {}

    def _save_cache(self) -> None:
        """Atomic write to cache file."""
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
        entry = self._cache.get(key)
        if isinstance(entry, dict):
            return entry
        return None

    def _put_cache(self, key: str, value: Dict[str, Any]) -> None:
        self._cache[key] = value
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
    budget = max_lookups
    try:
        origin_ip = result.get("origin_ip")
        if origin_ip and budget > 0:
            summary = state.vt_ip(origin_ip)
            if summary:
                enrichment["lookups"].append(
                    {"ioc": origin_ip, **summary}
                )
            budget -= 1

        iocs = result.get("iocs") or {}
        domains = (iocs.get("domains", {}).get("header", [])
                   + iocs.get("domains", {}).get("body", []))
        for domain in dict.fromkeys(domains):
            if budget <= 0:
                break
            summary = state.vt_domain(domain)
            if summary:
                enrichment["lookups"].append({"ioc": domain, **summary})
            budget -= 1
            if state.urlscan_key and budget > 0:
                us = state.urlscan_search(domain)
                if us:
                    enrichment["lookups"].append({"ioc": domain, **us})
                budget -= 1

        for att in iocs.get("attachment_hashes", []):
            if budget <= 0:
                break
            summary = state.vt_file_hash(att.get("sha256", ""))
            if summary:
                enrichment["lookups"].append(
                    {"ioc": att.get("filename", ""), **summary}
                )
            budget -= 1
    except Exception as exc:
        enrichment["errors"].append(f"enrichment failure: {type(exc).__name__}")

    enrichment["errors"].extend(state.errors[-5:])
    return enrichment
