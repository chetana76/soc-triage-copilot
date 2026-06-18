"""
Live grounding sources: NVD (CVE details + CVSS vector) and CISA KEV
(is this CVE being actively exploited right now).

Both calls are wrapped so a network failure degrades gracefully to whatever the
alert already carries, rather than crashing the pipeline. Disabled by default
(ENABLE_LIVE_NVD) so demos are reproducible.
"""

import requests
from . import config

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache = None


def enrich(cve_id):
    """
    Return {"cvss_vector": str|None, "on_kev": bool, "source": str}.
    Falls back to {} on any failure or when live lookups are disabled.
    """
    if not config.ENABLE_LIVE_NVD or not cve_id:
        return {}
    out = {"source": "live"}
    out["cvss_vector"] = _fetch_nvd_vector(cve_id)
    out["on_kev"] = _is_on_kev(cve_id)
    return out


def _fetch_nvd_vector(cve_id):
    try:
        headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=10)
        r.raise_for_status()
        metrics = r.json()["vulnerabilities"][0]["cve"]["metrics"]
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics:
                return metrics[key][0]["cvssData"]["vectorString"]
    except Exception:
        return None
    return None


def _is_on_kev(cve_id):
    global _kev_cache
    try:
        if _kev_cache is None:
            r = requests.get(KEV_URL, timeout=15)
            r.raise_for_status()
            _kev_cache = {v["cveID"] for v in r.json().get("vulnerabilities", [])}
        return cve_id in _kev_cache
    except Exception:
        return False
