"""STIX 2.1 / MISP export of extracted IOCs for SOC and TIP ingestion.

Purely local, dependency-free serializers: they transform the IOC dict already
produced by :func:`phishingclassifier.iocs.extract_iocs` into standard formats.
No network access and no new third-party packages.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from .iocs import all_domains, all_urls

_STIX_NS = uuid.NAMESPACE_URL
_SPEC = "2.1"


def _stix_id(stype: str, value: str) -> str:
    """Deterministic STIX id so repeated exports of the same IOC match."""
    return f"{stype}--{uuid.uuid5(_STIX_NS, f'{stype}:{value}')}"


def _collect(result: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten one analysis result into unique IOC collections."""
    iocs = result.get("iocs") or {}
    ip_bucket = iocs.get("ipv4", {})
    ips = set(ip_bucket.get("header", [])) | set(ip_bucket.get("body", []))
    if ip_bucket.get("origin"):
        ips.add(ip_bucket["origin"])
    if result.get("origin_ip"):
        ips.add(result["origin_ip"])

    email_bucket = iocs.get("emails", {})
    emails = set(email_bucket.get("header", [])) | set(email_bucket.get("body", []))
    if result.get("from"):
        emails.add(result["from"])

    return {
        "ipv4": sorted(ips),
        "domain": sorted(set(all_domains(iocs))),
        "url": sorted(set(all_urls(iocs))),
        "email-addr": sorted(emails),
        "files": iocs.get("attachment_hashes", []),
    }


def _stix_objects(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    c = _collect(result)
    objs: List[Dict[str, Any]] = []
    for ip in c["ipv4"]:
        objs.append(
            {
                "type": "ipv4-addr",
                "spec_version": _SPEC,
                "id": _stix_id("ipv4-addr", ip),
                "value": ip,
            }
        )
    for d in c["domain"]:
        objs.append(
            {
                "type": "domain-name",
                "spec_version": _SPEC,
                "id": _stix_id("domain-name", d),
                "value": d,
            }
        )
    for u in c["url"]:
        objs.append({"type": "url", "spec_version": _SPEC, "id": _stix_id("url", u), "value": u})
    for e in c["email-addr"]:
        objs.append(
            {
                "type": "email-addr",
                "spec_version": _SPEC,
                "id": _stix_id("email-addr", e),
                "value": e,
            }
        )
    for f in c["files"]:
        name = f.get("filename")
        sha = f.get("sha256")
        if not name:
            continue
        obj: Dict[str, Any] = {
            "type": "file",
            "spec_version": _SPEC,
            "id": _stix_id("file", sha or name),
            "name": name,
        }
        if sha:
            obj["hashes"] = {"SHA-256": sha}
        objs.append(obj)
    return objs


def stix_bundle(results: List[Dict[str, Any]]) -> str:
    """Return a STIX 2.1 bundle of every observable across the results."""
    seen: set = set()
    objects: List[Dict[str, Any]] = []
    for r in results:
        for obj in _stix_objects(r):
            if obj["id"] in seen:
                continue
            seen.add(obj["id"])
            objects.append(obj)
    objects.sort(key=lambda o: o["id"])
    seed = "|".join(o["id"] for o in objects) or "empty"
    bundle = {
        "type": "bundle",
        "spec_version": _SPEC,
        "id": f"bundle--{uuid.uuid5(_STIX_NS, 'phishsleuth:' + seed)}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False)


def _misp_event(result: Dict[str, Any]) -> Dict[str, Any]:
    c = _collect(result)
    attrs: List[Dict[str, Any]] = []
    for u in c["url"]:
        attrs.append({"type": "url", "category": "Network activity", "to_ids": True, "value": u})
    for d in c["domain"]:
        attrs.append({"type": "domain", "category": "Network activity", "to_ids": True, "value": d})
    for ip in c["ipv4"]:
        attrs.append(
            {"type": "ip-dst", "category": "Network activity", "to_ids": True, "value": ip}
        )
    for e in c["email-addr"]:
        attrs.append(
            {"type": "email-src", "category": "Payload delivery", "to_ids": False, "value": e}
        )
    for f in c["files"]:
        name = f.get("filename")
        sha = f.get("sha256")
        if not name:
            continue
        if sha:
            attrs.append(
                {
                    "type": "filename|sha256",
                    "category": "Payload delivery",
                    "to_ids": True,
                    "value": f"{name}|{sha}",
                }
            )
        else:
            attrs.append(
                {"type": "filename", "category": "Payload delivery", "to_ids": True, "value": name}
            )

    score = result.get("score") or {}
    now = datetime.now(timezone.utc)
    event = {
        "info": f"PhishSleuth: {result.get('subject') or '(no subject)'}",
        "timestamp": str(int(now.timestamp())),
        "date": now.strftime("%Y-%m-%d"),
        "threat_level_id": "2",
        "analysis": "0",
        "distribution": "0",
        "Attribute": attrs,
        "Tag": [
            {"name": f"phishsleuth:verdict={score.get('verdict', '')}"},
            {"name": f"phishsleuth:score={score.get('score', 0)}"},
        ],
    }
    return {"Event": event}


def misp_events(results: List[Dict[str, Any]]) -> str:
    """Return a JSON array of MISP events, one per analysed email."""
    return json.dumps([_misp_event(r) for r in results], indent=2, ensure_ascii=False)
