# AI investigation

Set `OPENAI_API_KEY` and `SENTINELX_AI_ALLOWED_ORGS` in the Enterprise API process environment. Set the allowlist to the comma-separated IDs of organizations authorized to send minimized investigation evidence externally. A signed-in administrator can find the organization ID in the authenticated `/api/me` response under `org_id`. Optionally set `SENTINELX_OPENAI_MODEL` to a model that supports Structured Outputs. The default is `gpt-5-mini`.

On Windows, configure the values in the shell or secret manager that starts Enterprise, then restart the Enterprise API. For Compose, use the backend variables from `.env.example` in your local `.env`. The API startup applies the additive AI report migration. You can also run `python -m alembic upgrade head` using the Enterprise database configuration. The API key belongs in the backend environment only. [OpenAI API quickstart](https://developers.openai.com/api/docs/quickstart)

Open an incident and use **Refresh Evidence**, **Investigate with AI**, or **Generate Full Report**. **Export Report** opens a print-ready report. Choose **Save as PDF** in the browser. Analysts can record review decisions and conclusions in the incident notes. A recommendation for the designated DemoLab account can be submitted to the existing Response Center, where the normal approval and execution flow applies.

At incident open, refresh, and report generation, the API reads the original alert evidence plus current events in the alert’s correlation window. Queries are scoped to the authenticated organization. The report keeps the evidence snapshot it analyzed. Refreshing evidence updates the current view and lets you decide whether to regenerate findings. The existing supporting-events panel continues to show the original alert evidence.

The external payload includes normalized event categories, opaque event IDs, timestamps, simulation flags, and derived alert metadata. Raw logs, IP addresses, asset names, analyst notes, and threat intelligence text stay local. The API requests Structured Outputs with response storage disabled and validates every event citation locally. Models have no execution tools. Each organization has up to ten requests per hour per API process. Calls use a finite timeout and one attempt per analyst request. Token counts are logged through the backend logger and retained with the saved report. [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) · [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create)

A configured legacy HTTPS gateway supports summary generation through the same organization allowlist. The draft’s evidence IDs must belong to the submitted evidence.

## Example report

Illustrative fixture for simulated failed logins. The IDs below identify fictional fixture records.

| Section | Example |
| --- | --- |
| Incident overview | Demo organization, alert `fixture-alert`, incident `fixture-case`, high severity, investigating. |
| Executive summary | Five simulated authentication failures were correlated for the designated test account. |
| Evidence analysis | Records `fixture-01` through `fixture-05` are failures. The fixture contains no successful sign-in evidence. |
| Attack timeline | 10:15:01, 10:15:04, 10:15:07, 10:15:10, and 10:15:13 UTC. |
| Possible root cause | The exercise is consistent with repeated credential guesses. In an observed incident, stale client credentials would be an alternative hypothesis. |
| MITRE ATT&CK mapping | Possible T1110 because the signal contains repeated authentication failures. |
| Threat intelligence | No completed external lookup is available. |
| Impact assessment | The test account was targeted by the simulated signal. Successful access was unverified. |
| Confidence and limitations | Strong confidence in the recorded failure sequence. Source IP and subsequent login outcomes were unavailable. |
| Investigation recommendations | Check for successful sign-ins after the failures, verify account ownership, and review MFA status. |
| Containment recommendations | If authorized, temporarily restrict the designated DemoLab account and record the approval. |
| Eradication and recovery | Restore the test account after verifying the outcome. For a real account, consider credential reset only if the evidence supports it. |
| Prevention | Review MFA, authentication rate limits, and alert thresholds. |
| Verification checklist | Confirm the intended access restriction, verify recovery, and look for renewed failures or unexpected successful sign-ins. |
| Final analyst conclusion | The simulated failure sequence is verified. The analyst should record the observed containment and recovery results. |

AI findings require analyst verification. Production usage limits are process-local. Automatic high-severity investigations and cost estimation are outside the current workflow. Source IP and detailed endpoint fields are available only when supported by the existing telemetry schema.


## Continuous monitoring

Selecting **Investigate** starts or resumes monitoring for the incident. Monitoring
uses the same organization, connector, asset, and simulation flag as the alert.
It considers supported security event categories from two minutes before the
selected alert onward and includes a bounded set of recent related alerts and
events in each snapshot. Telemetry stores one normalized asset field. Reports
can identify that recorded asset in the local incident overview. Separate user,
IP, host, or application identities require those fields in the telemetry.

The worker checks active cases in the background. It groups arrivals between
checks, skips unchanged model input, and waits five minutes after a provider
failure before retrying. An expired claim can be recovered after a restart.
Stopping or closing a case prevents future claims and discards an in-flight
result if the case was stopped before it could be saved. The report selector
shows the most recent 100 revisions. Export saves the displayed revision using
the browser print dialog. Prior reports are preserved during outages.

On Windows, run the updated backend and tests with a Python 3.12 installation
explicitly approved by Windows Application Control. The current uv-managed
interpreter was blocked, including when invoked through its virtual environment.
Create a virtual environment from the approved interpreter and install the
repository requirements. For staging, use a copy of the backed-up Enterprise
database via SENTINELX_DATABASE_URL, a separate loopback port, and a test
organization explicitly authorized for OpenAI. Run the documented Alembic
upgrade and backend tests against staging before replacing the running
Enterprise process. Configure backend secrets through the launch environment
or the approved secret manager.
