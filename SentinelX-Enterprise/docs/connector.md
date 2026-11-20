# Connector API

An administrator generates and copies a connector ID and token from Enterprise. Each token authorizes requests for its connector only. Enterprise stores the token digest. DemoLab stores its outgoing token in its isolated local database because it must present the token on subsequent requests.

Send JSON to `POST /api/connectors/{connector_id}/events`. Pass `Authorization: Bearer <connector token>`. Include the request Content-Length and keep the body under 16 KiB.

| Field | Meaning |
| --- | --- |
| `external_id` | Source-generated unique event identifier, 8–80 characters |
| `kind` | Lowercase normalized event name such as `connector_check`, `auth_failure`, or `app_error` |
| `asset` | Source-side asset identifier, up to 120 characters |
| `occurred` | UTC Unix time in seconds, 120 seconds behind to 30 seconds ahead of the server clock |
| `simulated` | Set to true for synthetic records |
| `source_ip` | Optional IPv4 or IPv6 client address. Displayed in Audit Logs for Login Portal authentication events. |
| `source_ip_simulated` | Optional flag for the configured demo fallback address. Accepted only on simulated Login Portal authentication events. |

Accepted submissions return HTTP 202 with the stored event ID and optionally a newly created alert ID. Duplicate source IDs return HTTP 409. Stale timestamps return HTTP 422. The connector accepts up to 120 events per rolling minute and returns HTTP 429 when the budget is exhausted.

Event ingestion and integration verification are separate operations. The signed-in organization administrator verifies a connector after a successful authenticated event arrives. Rotating credentials invalidates the previous token and requires a fresh event.

