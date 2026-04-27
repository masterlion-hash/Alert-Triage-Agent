"""
Creates the Alert Triage launcher panel in Kibana.

Reads connection details from environment variables (or your .env file).
Run from the project root:
    python deploy/create_canvas.py
"""

import base64
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Load .env if present
_env = Path(__file__).parent.parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

KIBANA_URL = os.environ.get("KIBANA_URL") or os.environ.get("ELASTIC_URL", "").replace(":9200", ":5601").replace(":9243", ":5601")
TRIAGE_URL = os.environ.get("PUBLIC_URL") or f"http://{KIBANA_URL.split('//')[1].split(':')[0]}:8000"
USERNAME   = os.environ.get("ELASTIC_USERNAME", "")
PASSWORD   = os.environ.get("ELASTIC_PASSWORD", "")

if not KIBANA_URL or not USERNAME or not PASSWORD:
    sys.exit(
        "ERROR: Set KIBANA_URL (or ELASTIC_URL), ELASTIC_USERNAME, and "
        "ELASTIC_PASSWORD in your .env file before running this script."
    )

_token  = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
HEADERS = {"Authorization": f"Basic {_token}", "kbn-xsrf": "true", "Content-Type": "application/json"}
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE


def _req(method, path, body=None):
    url  = KIBANA_URL.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, context=_SSL) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# ── Dashboard with Markdown visualization ────────────────────────────────────

VIS_ID  = "viz-alert-triage-btn"
DASH_ID = "dashboard-alert-triage"

MARKDOWN = f"""## Alert Triage & Investigation

Click the link below to open the triage panel from **any device**.

---

### [Open Alert Triage Panel]({TRIAGE_URL})

**What you get:**
- Live alert feed with severity, host, user, and rule filters
- Per-alert: host context, threat intel, related events
- AI verdict: TRUE_POSITIVE / FALSE_POSITIVE / INCONCLUSIVE

---

*MCP connector endpoint:* `{TRIAGE_URL}/mcp/mcp`
"""

VIS_ATTRS = {
    "title": "Alert Triage Launcher",
    "visState": json.dumps({
        "title": "Alert Triage Launcher",
        "type": "markdown",
        "params": {"markdown": MARKDOWN, "openLinksInNewTab": True},
        "aggs": [],
    }),
    "uiStateJSON": "{}",
    "description": "",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{}"},
}

DASH_ATTRS = {
    "title": "Alert Triage Panel",
    "description": "Launcher for the Alert Triage & Investigation tool",
    "panelsJSON": json.dumps([{
        "gridData": {"x": 0, "y": 0, "w": 48, "h": 20, "i": "1"},
        "panelIndex": "1",
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": "panel_1",
    }]),
    "optionsJSON": '{"hidePanelTitles":false,"useMargins":true}',
    "timeRestore": False,
    "kibanaSavedObjectMeta": {"searchSourceJSON": '{"query":{"language":"kuery","query":""},"filter":[]}'},
}


def main():
    print(f"Kibana : {KIBANA_URL}")
    print(f"Triage : {TRIAGE_URL}\n")

    print("Creating visualization ...")
    s, r = _req("POST", f"/api/saved_objects/visualization/{VIS_ID}", {"attributes": VIS_ATTRS})
    if s == 409:
        s, r = _req("PUT",  f"/api/saved_objects/visualization/{VIS_ID}", {"attributes": VIS_ATTRS})
    print(f"  vis: {s}")

    print("Creating dashboard ...")
    refs = [{"name": "panel_1", "type": "visualization", "id": VIS_ID}]
    s, r = _req("POST", f"/api/saved_objects/dashboard/{DASH_ID}", {"attributes": DASH_ATTRS, "references": refs})
    if s == 409:
        s, r = _req("PUT",  f"/api/saved_objects/dashboard/{DASH_ID}", {"attributes": DASH_ATTRS, "references": refs})
    print(f"  dashboard: {s}")

    if s in (200, 201):
        print(f"\nDone. Open: {KIBANA_URL}/app/dashboards#/view/{DASH_ID}")
    else:
        print(f"\nError: {r.get('message', r)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
