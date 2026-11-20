# SentinelX Enterprise

SentinelX Enterprise is a local, multi-organization security operations application. SentinelX DemoLab is a separate application with its own administrator, session cookie, and database. It sends labeled synthetic telemetry through the regular connector API.

## Windows 11 setup

Install Python 3.12 and Node.js 22 or newer. Open PowerShell in this folder.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm.cmd --prefix sentinelx-frontend ci
npm.cmd --prefix demolab/frontend ci
```

Start each backend and frontend from the project root in a separate PowerShell window.

```powershell
.\.venv\Scripts\python.exe -m uvicorn --app-dir sentinelx-backend app.main:app --host 127.0.0.1 --port 8001
```

```powershell
.\.venv\Scripts\python.exe -m uvicorn demolab.backend.main:app --host 127.0.0.1 --port 8002
```

```powershell
npm.cmd --prefix sentinelx-frontend run dev
```

```powershell
npm.cmd --prefix demolab/frontend run dev
```

Open Enterprise at [127.0.0.1:5174](http://127.0.0.1:5174) and DemoLab at [127.0.0.1:5175](http://127.0.0.1:5175). Keep the same hostname across each frontend and its navigation links for consistent sessions. The Vite servers use strict ports to avoid silently moving onto an unintended port. If a port is occupied, pass a free port to the relevant command and set the corresponding API origin, proxy target, or navigation link listed below.

| Setting | Default / purpose |
| --- | --- |
| `SENTINELX_DATABASE_URL` | `database/sentinelx.sqlite3` |
| `DEMOLAB_DATABASE_URL` | `database/demolab.sqlite3` |
| `SENTINELX_API` | Enterprise frontend proxy target, `http://127.0.0.1:8001` |
| `DEMOLAB_API` | DemoLab frontend proxy target, `http://127.0.0.1:8002` |
| `DEMOLAB_ENTERPRISE_URL` | Enterprise connector target, `http://127.0.0.1:8001` |
| `SENTINELX_ORIGINS`, `DEMOLAB_ORIGINS` | Comma-separated allowed browser origins |
| `VITE_DEMOLAB_URL`, `VITE_ENTERPRISE_URL` | Cross-application links |
| `SENTINELX_SECURE_COOKIES`, `DEMOLAB_SECURE_COOKIES` | Set to `1` for HTTPS |

For local Docker development, copy `.env.example` to `.env`, choose a URL-safe database password, and run `docker compose up --build`. PostgreSQL and DemoLab use separate persistent volumes. Both API backends run on loopback-published ports. DemoLab first-run setup is intended for the local operator.

## Demonstration

1. Register an organization in Enterprise and start integration onboarding. Choose **Website / Web Application** and generate credentials.
2. Open DemoLab, create its administrator with a separate password, and paste the connector ID and token under **Connector configuration**.
3. Click **Send verification event**. Return to Enterprise and choose **Verify event ingestion**, then **Open dashboard**.
4. In DemoLab, run **Failed sign-in attempts**. In Enterprise, open **Security Alerts**, then click **Investigate** beside the repeated authentication failures alert.
5. Review the evidence. Request test-account restriction and approve it in **Response Center**.
6. In DemoLab, click **Sync actions**, then **Check test-account access**. The sample business portal should report that access is restricted. Refresh the Response Center to read the recorded outcome.
7. Open the incident, request restoration, and approve it. Sync again in DemoLab and check that the test account can access its sample transactions.
8. Enter a resolution and close the incident. Download the incident report from its detail page.

## Validation and APIs

Run `python -m pytest -q` using the environment with the project dependencies. The integration test sends authenticated calls through both FastAPI apps and uses separate temporary databases. To repeat it over real HTTP, set `SENTINELX_TEST_HTTP=1` in the test shell. Run `npm.cmd --prefix sentinelx-frontend run build` and `npm.cmd --prefix demolab/frontend run build` to check the browser bundles.

The optional browser test uses an installed Chrome browser and temporary loopback ports. Build both frontends first, then run:

```powershell
npm.cmd install --prefix .deps-browser playwright-core
$env:SENTINELX_TEST_PYTHON = (Resolve-Path .\.venv\Scripts\python.exe).Path
node tests/browser-workflow.cjs
```

FastAPI exposes [Enterprise API documentation](http://127.0.0.1:8001/docs) and [DemoLab API documentation](http://127.0.0.1:8002/docs). See [Connector API](docs/connector.md) for the local event format. The initial Enterprise migration can also be run with `python -m alembic upgrade head`.

## Supported scope

Enterprise accepts normalized webhook telemetry. Wazuh, Suricata, endpoint, and cloud sources need their own forwarders to translate upstream events into the shared connector format. Administrators create one-time invitation codes in **Settings**. Members can save a one-time recovery code for password reset.

Investigations use a deterministic evidence summary and can request AI findings from the OpenAI Responses API or the optional legacy HTTPS gateway. [AI investigation setup and example report](docs/ai-investigation.md)

MISP uses published attribute search. TAXII uses a configured HTTPS collection objects endpoint and checks up to three pages for supported single-value STIX patterns. VirusTotal looks up existing reputation reports. These optional providers require credentials or authorized feeds to verify live results. [MISP API](https://misp.software/openapi/) · [TAXII specification](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.pdf) · [VirusTotal API](https://docs.virustotal.com/reference/overview)

DemoLab scenarios generate and persist bounded synthetic signals. The lab restriction changes the designated account state and expires after five minutes. For shared hosting, configure HTTPS, secure cookies, a secret store for the DemoLab connector token, and controlled administrator setup. The Compose configuration is for local development.

