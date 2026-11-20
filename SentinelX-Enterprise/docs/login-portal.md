# SentinelX Login Portal

Run the three services from the inner Enterprise checkout in separate Windows PowerShell terminals. The two database paths below are dedicated to this demo.

## Enterprise API

```powershell
Set-Location "$env:USERPROFILE/OneDrive/Desktop/SentinalX-Enterprise/SentinelX-Enterprise"
$env:SENTINELX_DATABASE_URL = 'sqlite:///database/sentinelx-login-isolated.sqlite3'
./.venv-ai-test/Scripts/python.exe -m uvicorn --app-dir sentinelx-backend app.main:app --host 127.0.0.1 --port 8003
```

## Login portal

Use a normal PowerShell session under your signed-in Windows account. Portal tokens are encrypted with that account's Windows DPAPI profile.

```powershell
Set-Location "$env:USERPROFILE/OneDrive/Desktop/SentinalX-Enterprise/SentinelX-Enterprise"
$env:LOGIN_PORTAL_DB = 'database/login-portal-isolated.sqlite3'
$env:LOGIN_PORTAL_DEVELOPMENT = '1'
./.venv-ai-test/Scripts/python.exe -m login_portal.server init-demo
Remove-Item Env:LOGIN_PORTAL_DEVELOPMENT
./.venv-ai-test/Scripts/python.exe -m uvicorn login_portal.server:app --host 127.0.0.1 --port 5500 --no-proxy-headers
```

The initializer prompts for separate passwords for the portal accounts **admin** and **demo**. Run it once per database. The portal accepts API URLs on loopback port 8003 by default. To approve a different destination, set **LOGIN_PORTAL_SENTINELX_URLS** to a comma-separated list of API origins before startup. Remote origins require HTTPS.

For a direct connection, keep `--no-proxy-headers` so the portal records the socket peer. For a reverse proxy deployment, replace it with `--proxy-headers --forwarded-allow-ips <proxy IP or CIDR>`. List only trusted proxies and configure them to set or sanitize `X-Forwarded-For`.

Update the Enterprise API before enabling the fallback. For an explicitly simulated demo only, set `LOGIN_PORTAL_SIMULATED_IP=192.0.2.10` before starting the portal. This labels the address as **Simulated IP** when a new attempt has no usable client address. Valid client addresses take precedence.

## SOC dashboard

```powershell
Set-Location "$env:USERPROFILE/OneDrive/Desktop/SentinalX-Enterprise/SentinelX-Enterprise"
$env:SENTINELX_API = 'http://127.0.0.1:8003'
npm.cmd --prefix sentinelx-frontend run dev -- --configLoader runner
```

1. Open the SOC dashboard at http://127.0.0.1:5174, register an isolated organization, and create an integration of type **Login Portal**. Copy its ID and token as a pair.
2. Open http://127.0.0.1:5500, sign in as portal **admin**, and open **Manage SentinelX integration**. Enter the API URL and the connector pair, then click **Connect**. The backend sends a verification event before saving the token. Select **Verify** for the connector in the SOC dashboard.
3. Sign out of the portal. Enter an incorrect password for **demo** three times within two minutes. Open **Security Alerts** for the high-severity detection and **Incidents** for the investigation. The dashboard refreshes both lists automatically.
4. To rotate credentials, rotate the token in the SOC dashboard, enter the new pair in the portal using **Update credentials**, then select **Verify** again in the SOC dashboard.

The **Login Portal** connector type enables the three-failure rule for that connector. The portal records attempts locally and retries queued events with their original timestamps and IDs while the connector accepts them. Attempts older than the API's two-minute acceptance window expire in the queue. The portal can still authenticate during an outage. Disconnecting clears the portal's stored credential and cancels queued delivery. Use **Disable** in the SOC dashboard to revoke access for that connector at Enterprise.

Enterprise opens the incident and schedules its existing investigation worker in the alert transaction. For a full AI report, provide **OPENAI_API_KEY** and the isolated organization's ID in **SENTINELX_AI_ALLOWED_ORGS** in the Enterprise API terminal before starting or restarting it. The organization ID is returned by **GET /api/me** from the authenticated SOC session. Without authorized provider access, the incident still shows the rule-based evidence and recommendations, and the AI monitor reports the provider failure.

Run the isolated integration test from the checkout with:

```powershell
./.venv-ai-test/Scripts/python.exe -m pytest -q tests/test_login_portal.py --basetemp ('.test-run-portal-' + [guid]::NewGuid().ToString('N'))
```
