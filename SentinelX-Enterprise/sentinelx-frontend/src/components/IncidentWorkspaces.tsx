import {useState} from 'react'
import {Link, useSearchParams} from 'react-router-dom'
import AIInvestigation from './AIInvestigation'
import {useData} from '../hooks/useData'
import {date, label} from '../services/api'
import '../styles/incident-workspace.css'

interface Incident {
  id: string
  alert_id: string
  title: string
  status: string
  created: number
}
interface IncidentAlert {id: string; label: string; severity: string; asset: string}
interface CaseContext extends Incident {
  eligible: boolean
  draft: {summary: string; evidence_ids: string[]} | null
}

function ReadError({message}: {message: string}) {
  return <p className="error" role="alert">{message}</p>
}

export function IncidentQueue() {
  const incidents = useData<Incident[]>('/api/incidents', 3000)
  const alerts = useData<IncidentAlert[]>('/api/alerts', 3000)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const alertById = new Map(alerts.data?.map(alert => [alert.id, alert]))
  const items = (incidents.data ?? []).map(incident => ({incident, alert: alertById.get(incident.alert_id)}))
  const statuses = [...new Set(items.map(({incident}) => incident.status))].sort()
  const severities = [...new Set(items.flatMap(({alert}) => alert ? [alert.severity] : []))].sort()
  const term = search.trim().toLowerCase()
  const matching = items.filter(({incident, alert}) => (
    (!status || incident.status === status) &&
    (!severity || alert?.severity === severity) &&
    [incident.title, incident.id, incident.alert_id, alert?.label, alert?.asset]
      .some(field => field?.toLowerCase().includes(term))
  ))
  return <div className="case-queue">
    <header className="page-heading">
      <h1>Incidents</h1>
      <p>Track cases, review supporting evidence, and manage the response.</p>
    </header>
    {incidents.error && <ReadError message={incidents.error}/>}
    {alerts.error && <ReadError message={'Related alert details could not be loaded. '+alerts.error}/>}
    <div className="panel case-filters">
      <label>Search incidents
        <input type="search" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Title, asset, incident ID, or alert ID"/>
      </label>
      <label><span id="case-status-label">Status</span>
        <select aria-labelledby="case-status-label" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {statuses.map(value => <option value={value} key={value}>{label(value)}</option>)}
        </select>
      </label>
      <label><span id="case-severity-label">Severity</span>
        <select aria-labelledby="case-severity-label" value={severity} onChange={e => setSeverity(e.target.value)} disabled={!alerts.data}>
          <option value="">All severities</option>
          {severities.map(value => <option value={value} key={value}>{label(value)}</option>)}
        </select>
      </label>
    </div>
    {!incidents.data && !incidents.error && <p role="status">Loading incidents…</p>}
    {incidents.data && <>
      <p className="case-results" role="status">{matching.length} of {items.length} incidents</p>
      {matching.length ? <div className="panel table-wrap">
        <table><thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Opened</th><th>Related alert</th></tr></thead>
          <tbody>{matching.map(({incident, alert}) => <tr key={incident.id}>
            <td><Link to={'/soc/incidents/'+incident.id}>{incident.title}</Link>
              {alert?.asset && <small className="case-secondary">{alert.asset}</small>}</td>
            <td>{alert ? <span className="badge case-severity" data-severity={alert.severity}>{alert.severity}</span> : 'Unavailable'}</td>
            <td><span className="badge">{label(incident.status)}</span></td>
            <td><time dateTime={new Date(incident.created*1000).toISOString()}>{date(incident.created)}</time></td>
            <td>{alert?.label ?? 'Alert ID'}<small className="case-secondary">{incident.alert_id}</small></td>
          </tr>)}</tbody>
        </table>
      </div> : <p className="panel">{items.length ? 'No incidents match your filters.' : 'No incidents have been opened.'}</p>}
    </>}
  </div>
}

function SelectedInvestigation({id, viewer}: {id: string; viewer: boolean}) {
  const path = '/api/incidents/'+encodeURIComponent(id)
  const query = useData<CaseContext>(path)
  const incident = query.data
  if (query.error) return <ReadError message={query.error}/>
  if (!incident) return <p role="status">Loading selected incident…</p>
  return <>
    <div className="panel ai-case-context">
      <div><h2>{incident.title}</h2><p>{label(incident.status)} · Opened {date(incident.created)}</p></div>
      <Link to={'/soc/incidents/'+encodeURIComponent(id)}>Open incident record</Link>
    </div>
    <AIInvestigation path={path} viewer={viewer} eligible={incident.eligible && incident.status !== 'closed'}
      existing={incident.draft} onReview={query.reload}/>
  </>
}

export function InvestigationWorkspace({viewer}: {viewer: boolean}) {
  const incidents = useData<Incident[]>('/api/incidents', 3000)
  const [params, setParams] = useSearchParams()
  const selected = params.get('incident') ?? ''
  const hasSelected = incidents.data?.some(incident => incident.id === selected)
  return <div className="ai-workspace">
    <header className="page-heading">
      <h1>AI Investigation</h1>
      <p>Review evidence, generate findings, and open saved reports for an incident.</p>
    </header>
    {incidents.error && <ReadError message={incidents.error}/>}
    <div className="panel ai-workspace-picker">
      <label><span id="ai-case-picker-label">Choose an incident</span>
        <select aria-labelledby="ai-case-picker-label" value={selected} disabled={!incidents.data?.length && !selected}
          onChange={e => setParams(e.target.value ? {incident:e.target.value} : {})}>
          <option value="">Select an incident</option>
          {selected && !hasSelected && <option value={selected}>Incident {selected}</option>}
          {incidents.data?.map(item => <option key={item.id} value={item.id}>
            {item.title} · {label(item.status)} · {date(item.created)} · {item.id.slice(0,8)}
          </option>)}
        </select>
      </label>
    </div>
    {selected ? <SelectedInvestigation key={selected} id={selected} viewer={viewer}/>
      : <p className="panel ai-workspace-empty">{incidents.data?.length
        ? 'Select an incident to load its evidence and saved AI results.'
        : incidents.data ? 'Open an incident from Security Alerts to begin an investigation.'
        : incidents.error ? 'The incident selector is unavailable.' : 'Loading incidents…'}</p>}
  </div>
}
