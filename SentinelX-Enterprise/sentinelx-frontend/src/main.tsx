import React, {FormEvent, ReactNode, useEffect, useState} from 'react'
import {createRoot} from 'react-dom/client'
import {BrowserRouter, Link, NavLink, Navigate, Route, Routes, useMatch, useNavigate, useParams} from 'react-router-dom'
import {Activity, ArrowDown, ArrowRight, ArrowUpRight, Bell, Cable, FileText, Fingerprint, LayoutDashboard, LockKeyhole, Radar, Radio, RefreshCw, Settings, Shield, ShieldAlert, Sparkles, Terminal, Workflow} from 'lucide-react'
import {motion} from 'framer-motion'
import {api, date, label} from './services/api'
import {useData} from './hooks/useData'
import {IncidentQueue, InvestigationWorkspace} from './components/IncidentWorkspaces'
import OverviewAnalytics, {AnalyticsSkeleton, OverviewMetrics, type OverviewData} from './components/OverviewAnalytics'
import './styles/site.css'

const kinds = ['Website / Web Application','Windows Endpoint','Wazuh','Suricata','Linux Server','Cloud Monitoring','Custom Webhook','DemoLab','Login Portal']
const labUrl = import.meta.env.VITE_DEMOLAB_URL || 'http://127.0.0.1:5175'
const pages = [
  ['Overview','overview',LayoutDashboard],['Live Monitoring','live',Radio],['Security Alerts','alerts',Bell],
  ['Incidents','incidents',ShieldAlert],['AI Investigation','investigation',Sparkles],
  ['Response Center','responses',Workflow],['Integrations','integrations',Cable],
  ['Reports','reports',FileText],['Audit Logs','audit',Fingerprint],['Settings','settings',Settings],
] as const
interface User {id:string; organization:string; name:string; onboarded:number; email:string; role:string}
interface Credentials {id:string; token:string}
interface Integration {id:string; kind:string; name:string; active:number; verified:number; last_event:number|null}
interface EventRow {id:string; kind:string; asset:string; simulated:number; occurred:number}
interface Alert {id:string; label:string; severity:string; asset:string; confidence:number; evidence:string[]; simulated:number; reason?:string; potential_threat?:string; recommended_actions?:string[]}
interface Incident {id:string; title:string; status:string; created:number; resolution?:string; assigned_to?:string}
interface Member {id:string; name:string; role:string}
interface Investigation extends Incident {summary:string; technique:string|null; confidence:number; impact:string; limitations:string; next_steps:string; recommendation:string; eligible:boolean; evidence: EventRow[]; notes:{author:string; body:string; created:number}[]; draft:{summary:string; evidence_ids:string[]}|null; timeline:{action:string;actor:string;created:number}[]}
interface Action {id:string; action:string; state:string; result:string|null; incident_id:string; approved_by:string|null}

function Brand() {
  return <Link to="/" className="brand"><span className="brand-icon"><Shield size={19}/></span><strong>Sentinel<span>X</span></strong><small>ENTERPRISE</small></Link>
}
function Heading({title, subtitle}:{title:string; subtitle:string}) {
  return <header className="page-heading"><h1>{title}</h1><p>{subtitle}</p></header>
}
function ErrorText({error}:{error?:string}) {return error ? <p className="error" role="alert">{error}</p> : null}
function Load({data,error,children}:{data:unknown; error?:string; children: ReactNode}) {
  return error ? <ErrorText error={error}/> : data === undefined ? <p className="muted" role="status">Loading…</p> : <>{children}</>
}
function useAction() {
  const [error,setError]=useState<string>(), [busy,setBusy]=useState(false)
  async function perform(action:()=>Promise<void>) {
    setError(undefined); setBusy(true)
    try {await action()} catch(e) {setError(e instanceof Error ? e.message : 'Request failed')} finally {setBusy(false)}
  }
  return {error,busy,perform}
}
function Landing() {
  return <main className="landing">
    <nav className="topbar"><Brand/><div className="top-links"><a href="#platform">Platform</a><a href="#integrations">Integrations</a><a href="#demo">DemoLab</a></div><div className="nav-actions"><Link to="/login">Sign in</Link><Link className="button compact" to="/register">Get Started <ArrowUpRight size={15}/></Link></div></nav>
    <section className="hero">
      <motion.div className="hero-content" initial={{opacity:0,y:14}} animate={{opacity:1,y:0}} transition={{duration:.55}}>
        <div className="eyebrow"><span className="status-dot"/> SECURITY OPERATIONS PLATFORM</div>
        <h1>Secure Every Connection.<br/><em>Detect Every Threat.</em></h1>
        <p>An intelligent security operations platform that unifies threat detection, monitoring, investigation, and incident response across your organization.</p>
        <div className="hero-actions"><Link className="button" to="/register">Get Started <ArrowRight size={17}/></Link><a className="button secondary" href="#platform">Explore Platform <ArrowDown size={16}/></a><a className="demo-link" href="#demo">View Demo <ArrowUpRight size={16}/></a></div>
      </motion.div>
      <div className="radar" aria-hidden="true"><div className="radar-cross"/><div className="radar-orbit orbit-one"/><div className="radar-orbit orbit-two"/><div className="radar-orbit orbit-three"/><div className="radar-orbit orbit-four"/><div className="radar-sweep"/><div className="radar-node node-one"/><div className="radar-node node-two"/><div className="radar-node node-three"/><div className="radar-shield"><Shield size={49} strokeWidth={1.25}/></div><div className="radar-left"><Radio size={15}/> Event ingestion</div><div className="radar-right"><LockKeyhole size={14}/> Tenant isolation</div></div>
      <div className="hero-line"><span><Radio size={16}/> LIVE TELEMETRY</span><span><Shield size={16}/> ORGANIZATION ISOLATION</span><span><Fingerprint size={16}/> TRACEABLE RESPONSE</span></div>
    </section>
    <section className="section" id="platform"><div className="eyebrow">THE PLATFORM</div><h2>From telemetry to resolution.</h2><div className="feature-grid">
      {[[Activity,'Security monitoring','Stream authenticated telemetry and see which assets and integrations are reporting.'],[Radar,'Threat detection','Correlate repeated events and inspect the evidence behind each alert.'],[Workflow,'Incident response','Review investigation findings, approve lab actions, and record execution and restoration.']].map(([Icon,title,copy])=>{const FeatureIcon=Icon as typeof Activity; return <article className="panel" key={String(title)}><FeatureIcon size={25}/><h3>{String(title)}</h3><p>{String(copy)}</p></article>})}</div></section>
    <section className="section split" id="integrations"><div><div className="eyebrow">INTEGRATIONS</div><h2>Connect the systems you monitor.</h2><p>Scope a credential to each source. Verify the connection by sending an authenticated event in the SentinelX format.</p><div className="pills">{kinds.map(kind=><span key={kind}>{kind}</span>)}</div></div><div className="panel"><h3>How SentinelX works</h3><ol className="steps"><li>Register your organization and generate a connector credential.</li><li>Send your first event and verify the integration.</li><li>Investigate correlated alerts and track approved responses.</li></ol></div></section>
    <section className="section" id="demo"><div className="panel demo-panel"><Terminal size={30}/><div><h2>Explore SentinelX DemoLab.</h2><p>Use labeled synthetic telemetry to see an alert through investigation, approval, and account restoration.</p></div><a className="button" href={labUrl}>Open DemoLab <ArrowUpRight size={16}/></a></div></section>
    <section className="section final-cta"><h2>Set up your security workspace.</h2><Link className="button" to="/register">Register an organization <ArrowRight size={16}/></Link></section>
    <footer className="topbar"><Brand/><a href="#platform">Platform overview</a><Link to="/login">Sign in</Link></footer>
  </main>
}
function Auth({register}:{register:boolean}) {
  const nav=useNavigate(), action=useAction()
  function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields=Object.fromEntries(new FormData(event.currentTarget))
    void action.perform(async()=>{const result=await api<{onboarded:boolean}>('/api/'+(register?'register':'login'),fields); nav(result.onboarded?'/soc/overview':'/onboarding',{replace:true})})
  }
  return <main className="auth"><Brand/><form className="panel auth-card" onSubmit={submit}>
    <div className="brand-icon"><LockKeyhole size={22}/></div><Heading title={register?'Create your organization':'Sign in to SentinelX'} subtitle={register?'Set up an isolated security workspace for your team.':'Access your organization’s security workspace.'}/>
    {register&&<><label>Organization name<input required name="organization" minLength={2} maxLength={100} autoComplete="organization"/></label><label>Administrator name<input required name="name" minLength={2} maxLength={100} autoComplete="name"/></label></>}
    <label>Work email<input required name="email" type="email" autoComplete="email" maxLength={254}/></label>
    <label>Password<input required name="password" type="password" minLength={register?12:1} maxLength={128} autoComplete={register?'new-password':'current-password'}/></label>
    {register&&<label>Confirm password<input required name="confirm" type="password" minLength={12} maxLength={128} autoComplete="new-password"/></label>}
    <ErrorText error={action.error}/><button className="button" disabled={action.busy}>{action.busy?'Please wait…':register?'Create organization':'Sign in'} <ArrowRight size={16}/></button>
    <Link to={register?'/login':'/register'}>{register?'Already registered? Sign in':'Create an organization'}</Link>
    {!register&&<div className="inline"><Link to="/join">Accept invitation</Link><Link to="/reset">Reset password</Link></div>}
  </form></main>
}
function AccountTokenForm({invite}:{invite:boolean}) {
  const nav=useNavigate(), action=useAction()
  return <main className="auth"><Brand/><form className="panel auth-card" onSubmit={e=>{
    e.preventDefault()
    const fields=Object.fromEntries(new FormData(e.currentTarget))
    void action.perform(async()=>{
      const data=await api<{onboarded?:boolean}>(invite?'/api/accept-invitation':'/api/reset-password',fields)
      nav(invite?(data.onboarded?'/soc/overview':'/onboarding'):'/login',{replace:true})
    })
  }}><Heading title={invite?'Accept organization invitation':'Reset your password'} subtitle={invite?'Enter the code supplied by your administrator.':'Enter the recovery code you generated in Settings.'}/>
    {invite&&<><label>Name<input name="name" required minLength={2}/></label><label>Work email<input name="email" type="email" required/></label></>}
    <label>{invite?'Invitation code':'Recovery code'}<input name="token" type="password" minLength={43} maxLength={43} required/></label>
    <label>New password<input name="password" type="password" minLength={12} maxLength={128} autoComplete="new-password" required/></label>
    <ErrorText error={action.error}/><button className="button" disabled={action.busy}>{invite?'Join organization':'Set new password'}</button><Link to="/login">Return to sign in</Link>
  </form></main>
}
function AccountSettings({user}:{user:User}) {
  const team=useData<Member[]>('/api/team'), action=useAction(), [token,setToken]=useState<{label:string; value:string}>()
  return <><Heading title="Settings" subtitle="Organization membership and account recovery"/>
    <div className="panel"><dl><dt>Organization</dt><dd>{user.organization}</dd><dt>Work email</dt><dd>{user.email}</dd><dt>Role</dt><dd>{user.role}</dd></dl>
      <button disabled={action.busy} onClick={()=>void action.perform(async()=>setToken({label:'One-time recovery code',value:(await api<{token:string}>('/api/recovery-code',{})).token}))}>Generate recovery code</button>
      <p>Save the code in a secure place. Generating a new code replaces the previous one.</p></div>
    <h3>Organization members</h3><Load data={team.data} error={team.error}><Table headers={['Name','Role']} rows={(team.data||[]).map(member=>[member.name,member.role])}/></Load>
    {user.role==='admin'&&<form className="panel" onSubmit={e=>{e.preventDefault();const fields=Object.fromEntries(new FormData(e.currentTarget));void action.perform(async()=>setToken({label:'Invitation code',value:(await api<{token:string}>('/api/invitations',fields)).token}))}}>
      <h3>Invite a member</h3><label>Work email<input name="email" type="email" maxLength={254} required/></label>
      <label>Role<select name="role"><option value="analyst">SOC Analyst</option><option value="viewer">Viewer</option></select></label>
      <button disabled={action.busy}>Create one-time invitation</button></form>}
    {token&&<div className="panel credential"><label>{token.label}<input readOnly value={token.value} onFocus={e=>e.target.select()}/></label><button onClick={()=>setToken(undefined)}>Hide code</button></div>}
    <ErrorText error={action.error}/>
  </>
}
function CredentialsPanel({value}:{value:Credentials}) {
  return <div className="credential panel"><h3>Connector credentials</h3><p>Copy this token now. Store it with your connector.</p><label>Connector ID<input readOnly value={value.id} onFocus={e=>e.target.select()}/></label><label>Connector token<input readOnly value={value.token} onFocus={e=>e.target.select()}/></label><p>Paste both values in DemoLab, or send normalized telemetry to this connector endpoint.</p><p className="font-mono break-all text-xs">POST /api/connectors/{value.id}/events</p><a href={labUrl} target="_blank" rel="noreferrer">Open DemoLab <ArrowUpRight size={14}/></a></div>
}
function IntegrationPicker({kind,onChange}:{kind:string;onChange:(value:string)=>void}) {
  return <fieldset><legend>Integration type</legend><div className="integration-options">{kinds.map(value=><label className={'choice '+(kind===value?'chosen':'')} key={value}><input type="radio" name="kind" value={value} checked={kind===value} onChange={()=>onChange(value)}/><Cable size={17}/>{value}</label>)}</div></fieldset>
}
function IntegrationForm({onCreate,busy,fixedKind}:{onCreate:(form:object)=>void; busy:boolean; fixedKind?:string}) {
  const [kind,setKind]=useState(kinds[0])
  return <form className="form-grid" onSubmit={e=>{e.preventDefault();onCreate(Object.fromEntries(new FormData(e.currentTarget)))}}>
    {fixedKind?<input type="hidden" name="kind" value={fixedKind}/>:<IntegrationPicker kind={kind} onChange={setKind}/>}
    <label>Integration name<input name="name" minLength={2} maxLength={100} required placeholder="Customer portal"/></label>
    <button className="button" disabled={busy}>Generate credentials <ArrowRight size={15}/></button>
  </form>
}
function Onboarding({user}:{user:User}) {
  const [step,setStep]=useState(0), [credentials,setCredentials]=useState<Credentials>(), [key,setKey]=useState('')
  const [kind,setKind]=useState(kinds[0])
  const saved=useData<Integration[]>('/api/integrations'), action=useAction(), nav=useNavigate()
  if (user.onboarded) return <Navigate to="/soc/overview" replace/>
  if (user.role!=='admin') return <main className="auth"><Brand/><section className="panel wizard"><Heading title="Waiting for onboarding" subtitle="Your organization administrator must verify the first integration."/><button onClick={()=>window.location.reload()}>Check again</button><button onClick={()=>void action.perform(async()=>{await api('/api/logout',{});nav('/login',{replace:true})})}>Sign out</button><ErrorText error={action.error}/></section></main>
  return <main className="auth onboarding"><Brand/><section className="panel wizard">
    <div className="wizard-progress">{['Welcome','Choose','Configure','Verify','Complete'].map((name,i)=><span key={name} aria-current={step===i?'step':undefined} className={step===i?'current':''}>{name}</span>)}</div>
    {step===0&&<><Heading title={'Welcome, '+user.organization} subtitle="Connect a source to start monitoring security events. Use DemoLab if you want to explore with synthetic telemetry."/><button className="button" onClick={()=>setStep(1)}>Choose an integration <ArrowRight size={16}/></button>{saved.data?.filter(item=>item.active).map(item=><button key={item.id} className="button secondary" onClick={()=>{setKey(item.id);setStep(3)}}>Resume verification for {item.name}</button>)}</>}
    {step===1&&<><Heading title="Choose a source" subtitle="Use DemoLab to verify with synthetic telemetry."/><IntegrationPicker kind={kind} onChange={setKind}/><button className="button" onClick={()=>setStep(2)}>Continue to configuration <ArrowRight size={16}/></button></>}
    {step===2&&<><Heading title="Configure a connection" subtitle={kind+' receives its own scoped credential.'}/><IntegrationForm busy={action.busy} fixedKind={kind} onCreate={fields=>void action.perform(async()=>{const value=await api<Credentials>('/api/integrations',fields);setKey(value.id);setCredentials(value);setStep(3)})}/><button className="button secondary" disabled={action.busy} onClick={()=>setStep(1)}>Back to source selection</button></>}
    {step===3&&<><Heading title="Verify your connection" subtitle="Send an authenticated event through the connector before verifying the integration."/>{credentials&&<CredentialsPanel value={credentials}/>}<button className="button" disabled={action.busy} onClick={()=>void action.perform(async()=>{await api('/api/integrations/'+key+'/verify',{});setCredentials(undefined);setStep(4)})}>{action.busy?'Verifying…':'Verify event ingestion'}</button>{!credentials&&<button className="button secondary" disabled={action.busy} onClick={()=>void action.perform(async()=>setCredentials(await api<Credentials>('/api/integrations/'+key+'/rotate',{})))}>Rotate credentials</button>}</>}
    {step===4&&<><Heading title="Integration verified" subtitle="SentinelX received an authenticated event for your organization."/><button className="button" onClick={()=>nav('/soc/overview',{replace:true})}>Open dashboard <ArrowRight size={16}/></button></>}
    <ErrorText error={action.error}/>
  </section></main>
}
function Guard({children}:{children:(user:User)=>ReactNode}) {
  const me=useData<User>('/api/me')
  if(me.error==='Sign in to continue') return <Navigate to="/login" replace/>
  return <Load data={me.data} error={me.error}>{me.data&&children(me.data)}</Load>
}
function Soc({user}:{user:User}) {
  const overview = useMatch('/soc/overview')
  const action=useAction(), nav=useNavigate()
  if(!user.onboarded) return <Navigate to="/onboarding" replace/>
  return <div className="soc"><aside><Brand/><div className="workspace"><span className="brand-icon">{user.organization.slice(0,1).toUpperCase()}</span><div><strong>{user.organization}</strong><small>Organization workspace</small></div></div>
    <nav>{pages.map(([name,path,Icon])=><NavLink key={path} to={'/soc/'+path}><Icon size={18}/>{name}</NavLink>)}</nav>
    <div className="sidebar-bottom"><strong>{user.name}</strong><small>{user.role}</small><button disabled={action.busy} onClick={()=>void action.perform(async()=>{await api('/api/logout',{});nav('/login',{replace:true})})}>Sign out</button><ErrorText error={action.error}/></div>
  </aside><main className={overview ? "console overview-console" : "console"}>{!overview&&<div className="console-top"><span>Security operations</span><span><i className="status-dot"/> {user.organization}</span></div>}<Routes>
    <Route index element={<Navigate to="overview" replace/>}/><Route path="overview" element={<Dashboard/>}/><Route path="live" element={<Live/>}/><Route path="events/:id" element={<EventDetail/>}/>
    <Route path="alerts" element={<Alerts user={user}/>}/><Route path="incidents" element={<IncidentQueue/>}/><Route path="incidents/:id" element={<IncidentView user={user}/>}/>
    <Route path="investigation" element={<InvestigationWorkspace viewer={user.role==='viewer'}/>}/><Route path="reports" element={<Reports/>}/>
    <Route path="responses" element={<Responses user={user}/>}/><Route path="integrations" element={<Integrations user={user}/>}/>
    <Route path="audit" element={<Audit/>}/>
    <Route path="settings" element={<AccountSettings user={user}/>}/>
    <Route path="*" element={<Navigate to="/soc/overview" replace/>}/>
  </Routes></main></div>
}
function Dashboard() {
  const query=useData<OverviewData>('/api/overview',5000)
  const [updated, setUpdated] = useState<Date>()
  useEffect(() => {
    if (query.data) setUpdated(new Date())
  }, [query.data])
  return <>
    <header className="overview-heading">
      <div><h1>Security Overview</h1><p>Real-time security monitoring and incident insights</p></div>
      <button className="overview-refresh" onClick={query.reload} aria-label="Refresh overview">
        <RefreshCw size={15} aria-hidden="true"/>
        {updated ? 'Last updated: '+updated.toLocaleString([], {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}) : 'Refresh'}
      </button>
    </header>
    {!query.data&&!query.error&&<AnalyticsSkeleton/>}
    <ErrorText error={query.error}/>
    {query.data&&<><OverviewMetrics data={query.data}/><OverviewAnalytics data={query.data}/></>}
  </>
}
function Table({headers,rows}:{headers:string[]; rows:ReactNode[][]}) {
  return <div className="panel table-wrap">{rows.length?<table><thead><tr>{headers.map(name=><th key={name}>{name}</th>)}</tr></thead><tbody>{rows.map((row,index)=><tr key={index}>{row.map((cell,i)=><td key={i}>{cell}</td>)}</tr>)}</tbody></table>:<p className="empty">No records to display.</p>}</div>
}
function EventTable({events}:{events:EventRow[]}) {
  return <Table headers={['Event','Asset','Source','Occurred']} rows={events.map(row=>[<Link to={'/soc/events/'+row.id}>{label(row.kind)}</Link>,row.asset,row.simulated?<span className="badge">Simulated</span>:'Observed',date(row.occurred)])}/>
}
function Live() {
  const [events,setEvents]=useState<EventRow[]>(),[status,setStatus]=useState('Connecting…'),[filter,setFilter]=useState('')
  useEffect(()=>{const stream=new EventSource('/api/live');stream.onmessage=e=>{setEvents(JSON.parse(e.data));setStatus('Live')};stream.onerror=()=>setStatus('Reconnecting…');return ()=>stream.close()},[])
  const kinds=[...new Set(events?.map(row=>row.kind))]
  return <><Heading title="Live monitoring" subtitle="The 30 most recently received events for this organization."/><div className="toolbar"><span className="badge" role="status">{status}</span><label>Event type<select value={filter} onChange={e=>setFilter(e.target.value)}><option value="">All events</option>{kinds.map(kind=><option key={kind} value={kind}>{label(kind)}</option>)}</select></label></div>{events&&<EventTable events={events.filter(row=>!filter||filter===row.kind)}/>}</>
}
function EventDetail() {
  const {id}=useParams(), query=useData<EventRow>('/api/events/'+id)
  return <><Heading title="Event evidence" subtitle={id||''}/><Load data={query.data} error={query.error}>{query.data&&<div className="panel"><dl><dt>Event type</dt><dd>{label(query.data.kind)}</dd><dt>Asset</dt><dd>{query.data.asset}</dd><dt>Source</dt><dd>{query.data.simulated?'Simulated':'Observed'}</dd><dt>Occurred</dt><dd>{date(query.data.occurred)}</dd></dl></div>}</Load></>
}
function Alerts({user}:{user:User}) {
  const query=useData<Alert[]>('/api/alerts', 3000), action=useAction(), nav=useNavigate()
  return <><Heading title="Security alerts" subtitle="Correlated activity and the evidence behind each detection."/><ErrorText error={action.error}/><Load data={query.data} error={query.error}><Table headers={['Detection','Severity','Asset','Evidence','Investigation']} rows={(query.data||[]).map(row=>[<>{row.label}{row.reason&&<details><summary>Detection details</summary><p>{row.reason}</p><p>{row.potential_threat}</p><ul>{row.recommended_actions?.map(item=><li key={item}>{item}</li>)}</ul></details>}{row.simulated&&<span className="badge">Simulated</span>}</>,row.severity,row.asset,row.evidence.length,user.role==='viewer'?'Analyst access required':<button disabled={action.busy} onClick={()=>void action.perform(async()=>{const result=await api<{id:string}>('/api/alerts/'+row.id+'/incident',{});nav('/soc/incidents/'+result.id)})}>Investigate</button>])}/></Load></>
}
function Reports() {
  const query=useData<Incident[]>('/api/incidents', 3000)
  return <><Heading title="Reports" subtitle="Open an incident to download its evidence and resolution report."/><Load data={query.data} error={query.error}><Table headers={['Incident','Status','Opened']} rows={(query.data||[]).map(row=>[<Link to={'/soc/incidents/'+row.id}>{row.title}</Link>,<span className="badge">{row.status}</span>,date(row.created)])}/></Load></>
}
function IncidentView({user}:{user:User}) {
  const {id}=useParams(), path='/api/incidents/'+id, query=useData<Investigation>(path), action=useAction(), nav=useNavigate()
  const team=useData<Member[]>('/api/team')
  function save(e:FormEvent<HTMLFormElement>, operation:string) {
    e.preventDefault();const form=e.currentTarget, fields=Object.fromEntries(new FormData(form))
    void action.perform(async()=>{await api(path+'/'+operation,fields);form.reset();query.reload()})
  }
  const report=query.data
  function download() {
    const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}))
    const link=document.createElement('a');link.href=url;link.download='sentinelx-incident-'+id+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
  }
  return <><Heading title={report?.title||'Incident investigation'} subtitle={id||''}/><ErrorText error={action.error}/><Load data={report} error={query.error}>{report&&<>
    <div className="panel"><div className="toolbar"><span className="badge">{report.status}</span><span className="badge">Evidence rules</span><button onClick={download}>Download report</button><Link to={'/soc/investigation?incident='+encodeURIComponent(report.id)}>Open AI Investigation</Link></div><h3>Investigation summary</h3><p>{report.summary}</p><dl><dt>Potential impact</dt><dd>{report.impact}</dd><dt>Possible technique</dt><dd>{report.technique||'No mapping for this rule'}</dd><dt>Confidence</dt><dd>{report.confidence}% · rule estimate</dd><dt>Limitations</dt><dd>{report.limitations}</dd><dt>Next steps</dt><dd>{report.next_steps}</dd><dt>Suggested response</dt><dd>{report.recommendation}</dd>{report.resolution&&<><dt>Resolution</dt><dd>{report.resolution}</dd></>}</dl></div>

    <h3>Supporting events</h3><EventTable events={report.evidence}/><h3>Investigation notes</h3><Table headers={['Author','Note','Time']} rows={report.notes.map(note=>[note.author,note.body,date(note.created)])}/>
    <h3>Incident timeline</h3><Table headers={['Action','Actor','Time']} rows={report.timeline.map(item=>[item.action,item.actor,date(item.created)])}/>
    <div className="panel"><h3>Assignee</h3><p>{team.data?.find(member=>member.id===report.assigned_to)?.name||'Unassigned'}</p>
      {user.role!=='viewer'&&report.status!=='closed'&&<form onSubmit={e=>save(e,'assign')}><label>Assign analyst<select name="user_id" required defaultValue=""><option value="">Choose a member</option>{team.data?.filter(member=>member.role!=='viewer').map(member=><option key={member.id} value={member.id}>{member.name}</option>)}</select></label><button disabled={action.busy}>Assign</button></form>}
    </div>
    {user.role!=='viewer'&&<div className="panel"><form onSubmit={e=>save(e,'notes')}><label>Investigation note<textarea name="body" required maxLength={4000}/></label><button disabled={action.busy}>Add note</button></form>
    {report.status!=='closed'&&<>{report.eligible&&<div className="toolbar"><button disabled={action.busy} onClick={()=>void action.perform(async()=>{await api(path+'/responses/restrict_test_account',{});nav('/soc/responses')})}>Request test-account restriction</button><button disabled={action.busy} onClick={()=>void action.perform(async()=>{await api(path+'/responses/restore_test_account',{});nav('/soc/responses')})}>Request account restoration</button></div>}<form onSubmit={e=>save(e,'close')}><label>Resolution<textarea name="body" required maxLength={4000}/></label><button disabled={action.busy}>Close incident</button></form></>}</div>}
  </>}</Load></>
}
function Responses({user}:{user:User}) {
  const query=useData<Action[]>('/api/responses'), action=useAction()
  return <><Heading title="Response Center" subtitle="Review and approve DemoLab actions. Sync approved actions from DemoLab to execute them."/><div className="panel"><h3>Target and risk</h3><p>Actions affect only the designated DemoLab test account. Restriction blocks the failed-login scenario for up to five minutes. Approve a restoration request to reverse it immediately.</p><a href={labUrl} target="_blank" rel="noreferrer">Open DemoLab <ArrowUpRight size={14}/></a></div><div className="toolbar"><button onClick={query.reload}>Refresh status</button></div><ErrorText error={action.error}/><Load data={query.data} error={query.error}><Table headers={['Action','Incident','Status','Result','Approval']} rows={(query.data||[]).map(row=>[label(row.action),<Link to={'/soc/incidents/'+row.incident_id}>Open incident</Link>,<span className="badge">{row.state}</span>,row.result||'Awaiting result',row.state==='pending'&&user.role!=='viewer'?<div className="inline">{['approve','reject'].map(decision=><button key={decision} disabled={action.busy} onClick={()=>void action.perform(async()=>{await api('/api/responses/'+row.id+'/'+decision,{});query.reload()})}>{decision}</button>)}</div>:row.approved_by?'Decision recorded':'Pending'])}/></Load></>
}
function Integrations({user}:{user:User}) {
  const query=useData<Integration[]>('/api/integrations'), action=useAction(), [credentials,setCredentials]=useState<Credentials>(), [add,setAdd]=useState(false)
  const [activity,setActivity]=useState<Integration>()
  return <><Heading title="Integrations" subtitle="Manage scoped connectors and verify recent event delivery."/><ErrorText error={action.error}/>{user.role==='admin'&&<div className="toolbar"><button className="button" onClick={()=>setAdd(!add)}>{add?'Close setup':'Add integration'}</button></div>}
    {add&&<div className="panel"><IntegrationForm busy={action.busy} onCreate={fields=>void action.perform(async()=>{setCredentials(await api<Credentials>('/api/integrations',fields));setAdd(false);query.reload()})}/></div>}
    {credentials&&<><CredentialsPanel value={credentials}/><button onClick={()=>setCredentials(undefined)}>Hide credentials</button></>}
    <Load data={query.data} error={query.error}><Table headers={['Integration','Type','Health','Last event','Operations']} rows={(query.data||[]).map(row=>[row.name,row.kind,<span className="badge">{!row.active?'Disconnected':!row.verified?'Configuration required':row.last_event&&Date.now()/1000-row.last_event<=300?'Receiving events':'Connected'}</span>,row.last_event?date(row.last_event):'Awaiting event',<div className="inline"><button onClick={()=>setActivity(row)}>Activity</button>{user.role==='admin'&&(row.active?['verify','rotate','disable','remove']:['reconnect','remove']).map(operation=><button key={operation} disabled={action.busy} onClick={()=>void action.perform(async()=>{if(operation==='remove'&&!confirm('Remove this connector credential? Historical evidence will be retained.'))return;const result=await api<Credentials>('/api/integrations/'+row.id+'/'+operation,{});setCredentials(result.token?result:undefined);query.reload()})}>{operation==='verify'?'Test connection':operation}</button>)}</div>])}/></Load>
    {activity&&<IntegrationActivity item={activity} onClose={()=>setActivity(undefined)}/>}
  </>
}
function IntegrationActivity({item,onClose}:{item:Integration;onClose:()=>void}) {
  const history=useData<EventRow[]>('/api/integrations/'+item.id+'/activity')
  return <section><div className="toolbar"><h3>Recent activity for {item.name}</h3><button onClick={history.reload}>Refresh activity</button><button onClick={onClose}>Close activity</button></div><Load data={history.data} error={history.error}>{history.data&&<EventTable events={history.data}/>}</Load></section>
}
const auditMissing='\u2014'
const auditDate=new Intl.DateTimeFormat('en-GB',{day:'2-digit',month:'2-digit',year:'numeric'})
const auditTime=new Intl.DateTimeFormat('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:true})
// Audit ingestion emits these action codes only for Login Portal connector attempts.
const isPortalAttempt=(action:string)=>action==='auth_success'||action==='auth_failure'
function Audit() {
  const [view, setView]=useState<'authentication'|'all'>('authentication')
  const query=useData<{source_ip?:string|null;source_ip_simulated?:number;action:string;actor:string;target:string;created?:number|null}[]>(
    '/api/audit?view='+view, 3000)
  const records=query.data?.filter(row=>view==='all'||isPortalAttempt(row.action))
  return <><Heading title="Audit logs" subtitle="Organization activity and recorded changes."/>
    <div className="toolbar"><label>Audit view
      <select aria-label="Audit view" value={view} onChange={event=>setView(event.target.value==='all'?'all':'authentication')}>
        <option value="authentication">Login Attempts</option>
        <option value="all">All Activity</option>
      </select>
    </label></div>
    <Load data={query.data} error={query.error}>
      {records?.length===0&&view==='authentication'
        ? <p className="panel empty">No login attempts have been received.</p>
        : <Table headers={['IP Address','Actor','Target','Date','Time']} rows={(records||[]).map(row=>{
          const timestamp=typeof row.created==='number' ? new Date(row.created*1000) : null
          const recorded=timestamp&&Number.isFinite(timestamp.getTime()) ? timestamp : null
          return [
            row.source_ip ? <>{row.source_ip}{row.source_ip_simulated===1&&<span className="badge">Simulated IP</span>}</> : auditMissing,
            isPortalAttempt(row.action)?'Login Portal':row.actor,row.target,
            recorded ? <time dateTime={recorded.toISOString()}>{auditDate.format(recorded)}</time> : auditMissing,
            recorded ? <time dateTime={recorded.toISOString()}>{auditTime.format(recorded)}</time> : auditMissing,
          ]
        })}/>}
    </Load></>
}
function App() {
  return <BrowserRouter><Routes><Route path="/" element={<Landing/>}/><Route path="/register" element={<Auth key="register" register/>}/><Route path="/login" element={<Auth key="login" register={false}/>}/><Route path="/join" element={<AccountTokenForm invite/>}/><Route path="/reset" element={<AccountTokenForm invite={false}/>}/><Route path="/onboarding" element={<Guard key="onboarding">{user=><Onboarding user={user}/>}</Guard>}/><Route path="/soc/*" element={<Guard key="soc">{user=><Soc user={user}/>}</Guard>}/><Route path="*" element={<Navigate to="/" replace/>}/></Routes></BrowserRouter>
}
createRoot(document.getElementById('root')!).render(<App/>)

