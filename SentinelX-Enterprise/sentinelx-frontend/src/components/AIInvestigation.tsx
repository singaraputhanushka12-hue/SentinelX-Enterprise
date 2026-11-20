import {useEffect,useState} from 'react'
import {Link} from 'react-router-dom'
import {api,date,label} from '../services/api'
import {useData} from '../hooks/useData'

interface Evidence {
  alert:{id:string;integration_id:string;rule:string;severity:string;asset:string;created:number;simulated:number}
  incident_id:string
  status:string
  fetched:number
  events:{id:string;kind:string;occurred:number;simulated:number}[]
  intelligence:{source:string;reputation:string;confidence:number|null;checked:number}[]
  notes:{author:string;body:string;created:number}[]
  related:{id:string;rule:string;severity:string;created:number}[]
}
interface Context {
  evidence:Evidence
  organization:string
  status:{ready:boolean;provider:string|null;message:string}
  sections:Record<string,string>
  saved:Snapshot|null
  monitor:{state:string;updated:number;error:string|null}|null
  current_revision:string|null
  revisions:{id:string;mode:string;created:number}[]
}
interface Report {
  provider:string
  generated:number
  findings:Record<string,{text:string;event_ids:string[]}>
}
interface Snapshot {report:Report;evidence:Evidence}
interface Generation {generated:boolean;message?:string;report?:Report;evidence?:Evidence;revision?:string}

function printReport(context:Context, report:Report, evidence:Evidence, conclusion:string, revision:string) {
  const page=window.open('','_blank','width=900,height=740')
  if(!page) throw new Error('Allow the report window to open, then try Export Report again.')
  const doc=page.document
  doc.title='SentinelX investigation '+evidence.incident_id
  const css=doc.createElement('style')
  css.textContent='body{font:12pt/1.5 system-ui;color:#17243a;margin:2rem}h2{break-after:avoid;margin-top:1.5rem}p{white-space:pre-wrap;overflow-wrap:anywhere}@page{margin:17mm}'
  doc.head.append(css)
  function write(tag:string, value:string) {
    const node=doc.createElement(tag)
    node.textContent=value
    doc.body.append(node)
  }
  write('h1','SentinelX investigation report')
  write('p',context.organization+' · Generated '+date(report.generated)+' · '+report.provider)
  write('p','AI-generated findings require analyst verification.')
  if(revision) write('p','Revision '+revision)
  write('h2','Incident overview')
  write('p',evidence.alert.id+' / '+evidence.incident_id+'\n'+label(evidence.alert.rule)+' · '+evidence.alert.severity+' · '+evidence.status+'\n'+evidence.alert.asset+' · '+date(evidence.alert.created))
  write('h2','Evidence timeline')
  for(const event of evidence.events) write('p',date(event.occurred)+' · '+label(event.kind)+' · '+event.id+(event.simulated?' · Simulated':''))
  write('h2','Threat intelligence')
  for(const line of intelLines(evidence)) write('p',line)
  for(const [key,finding] of Object.entries(report.findings)) {
    write('h2',context.sections[key]||key)
    write('p',finding.text)
    if(finding.event_ids.length)write('p','Cited events — '+finding.event_ids.join(', '))
  }
  if(conclusion.trim()){write('h2','Analyst-edited conclusion');write('p',conclusion)}
  write('h2','Analyst notes')
  for(const note of evidence.notes)write('p',note.author+' · '+date(note.created)+'\n'+note.body)
  page.focus()
  page.print()
}
function intelLines(evidence:Evidence) {
  const available=evidence.intelligence.filter(item=>!['Not configured','Provider unavailable','Provider endpoint unavailable'].includes(item.reputation))
  return available.length?available.map(item=>item.source+' · '+item.reputation+' · '+date(item.checked)) : ['No completed external intelligence lookup is stored for this asset.']
}

export default function AIInvestigation({path,viewer,eligible,existing,onReview}:{path:string;viewer:boolean;eligible:boolean;existing:{summary:string;evidence_ids:string[]}|null;onReview:()=>void}) {
  const query=useData<Context>(path+'/ai-evidence')
  const [selected,setSelected]=useState<{id:string;snapshot:Snapshot}>()
  const {reload}=query
  const [busy,setBusy]=useState(''),[message,setMessage]=useState(''),[error,setError]=useState('')
  const [conclusion,setConclusion]=useState(''),[note,setNote]=useState('')
  async function run(activity:string,work:()=>Promise<void>){
    setBusy(activity);setError('');setMessage('')
    try{await work()}catch(err){setError(err instanceof Error?err.message:'Request failed')}finally{setBusy('')}
  }
  function generate(mode:'quick'|'full'){
    void run('Generating investigation…',async()=>{
      const result=await api<Generation>(path+'/ai-report',{mode})
      if(!result.generated||!result.report||!result.evidence)throw new Error(result.message||'No report was generated.')
      if(result.revision)setSelected({id:result.revision,snapshot:{report:result.report,evidence:result.evidence}})
      setConclusion(result.report.findings.conclusion?.text||'')
      query.reload()
      setMessage('Draft generated and ready for analyst review.')
    })
  }
  const context=query.data
  const current=context?.evidence
  const snapshot=selected?.snapshot||context?.saved
  const monitor=context?.monitor
  const requestError=error||query.error
  const active=!!monitor&&monitor.state!=='stopped'
  const integration=current?.alert.integration_id
  const asset=current?.alert.asset
  const simulated=current?.alert.simulated
  useEffect(()=>{
    if(!active) return
    const timer=window.setInterval(reload,5000)
    const stream=typeof EventSource==='undefined'?null:new EventSource('/api/live')
    if(stream)stream.onmessage=message=>{
      const events=JSON.parse(message.data) as {integration_id:string;asset:string;simulated:number}[]
      if(events.some(event=>event.integration_id===integration&&event.asset===asset&&event.simulated===simulated))reload()
    }
    return ()=>{
      window.clearInterval(timer)
      stream?.close()
    }
  },[active,integration,asset,simulated,reload])
  function selectRevision(id:string) {
    if(!id){setSelected(undefined);setConclusion('');return}
    void run('Loading report revision?',async()=>{
      const revision=await api<Snapshot>(path+'/ai-revisions/'+id)
      setSelected({id,snapshot:revision})
      setConclusion('')
    })
  }
  return <section className="panel ai-investigation-panel" aria-label="AI investigation">
    <h3>AI investigation</h3>
    <div className="ai-investigation-status"><h4>Provider and monitoring status</h4>
    <p>{context?((context.status.provider?context.status.provider+' · ':'')+context.status.message):query.error?'Evidence could not be loaded.':'Loading provider status and evidence…'}</p>
    {monitor&&<p role="status">{monitor.state.charAt(0).toUpperCase()+monitor.state.slice(1)} &middot; Last updated {date(monitor.updated)}</p>}
    {monitor?.error&&<p className="error" role="alert">{monitor.error}</p>}
    {!monitor&&context&&<p>Continuous monitoring has not started.</p>}</div>
    <div className="toolbar">
      {!viewer&&current&&current.status!=='closed'&&
        <button disabled={!!busy} onClick={()=>void run('Updating monitoring?',async()=>{
          await api(path+'/ai-monitor',{active:!active})
          reload()
        })}>{active?'Stop monitoring':monitor?'Resume monitoring':'Start monitoring'}</button>}
      <button disabled={!!busy} onClick={()=>{query.reload();setMessage('');setError('')}}>Refresh Evidence</button>
      {!viewer&&<><button disabled={!!busy||!context?.status.ready} onClick={()=>generate('quick')}>Generate Investigation</button><button disabled={!!busy||!context?.status.ready||!['OpenAI','Gemini'].includes(context.status.provider || '')} onClick={()=>generate('full')}>Generate Report</button></>}
      {context&&snapshot&&<button disabled={!!busy} onClick={()=>void run('Preparing export…',async()=>printReport(context,snapshot.report,snapshot.evidence,conclusion,selected?.id||context.current_revision||''))}>Export Report</button>}
    </div>
    {!!context?.revisions?.length&&<label>Report revision
      <select disabled={!!busy} value={selected?.id||''} onChange={event=>selectRevision(event.target.value)}>
        <option value="">Current report</option>
        {context.revisions.map(revision=><option key={revision.id} value={revision.id}>
          {date(revision.created)} ? {label(revision.mode)} ? {revision.id.slice(0,8)}
        </option>)}
      </select>
    </label>}
    {(busy||message)&&<p role="status">{busy||message}</p>}
    {requestError&&requestError!==monitor?.error&&<p className="error" role="alert">{requestError}</p>}
    {current&&<details><summary>Current evidence · {current.events.length} events · refreshed {date(current.fetched)}</summary>
      <p>{label(current.alert.rule)} · {current.alert.severity} · {current.alert.asset} · {current.status} · {current.related.length} related alerts</p>
      <ul>{current.events.map(event=><li key={event.id}>{date(event.occurred)} · {label(event.kind)} · <Link to={'/soc/events/'+event.id}>{event.id}</Link></li>)}</ul>
      {!!current.related.length&&<><h4>Related alerts</h4><ul>{current.related.map(alert=>
        <li key={alert.id}>{date(alert.created)} ? {label(alert.rule)} ? {alert.severity} ? {alert.id}</li>)}</ul></>}
      <h4>Threat intelligence</h4><ul>{intelLines(current).map((line,i)=><li key={i}>{line}</li>)}</ul>
      <p>Last recorded review · {current.notes.filter(note=>note.body.startsWith('AI review')).at(-1)?.body.split('\n')[0]||'Awaiting analyst review'}</p>
    </details>}
    {!snapshot&&existing&&<div><h4>Saved AI draft</h4><p>{existing.summary}</p><div className="inline">{existing.evidence_ids.map(id=><Link key={id} to={'/soc/events/'+id}>{id}</Link>)}</div></div>}
    {!snapshot&&!existing&&context&&<p>No AI findings are saved for this incident.</p>}
    {snapshot&&context&&<>
      <p className="badge">AI draft · analyst verification required</p>
      <p>Generated {date(snapshot.report.generated)} &middot; {snapshot.report.provider}</p>
      <div className="ai-findings">{Object.entries(snapshot.report.findings).map(([name,finding])=><article className="ai-finding" key={name}>
        <h4>{context.sections[name]||label(name)}</h4><p>{finding.text}</p>
        <div className="inline">{finding.event_ids.map(id=><Link key={id} to={'/soc/events/'+id}>{id}</Link>)}</div>
      </article>)}</div>
      {!viewer&&<div className="ai-review"><label>Analyst conclusion<textarea maxLength={1800} value={conclusion} onChange={event=>setConclusion(event.target.value)}/></label>
      <h4>Recommended Actions</h4>
      {eligible?<><p>Temporarily restrict the designated DemoLab test account after verifying the repeated simulated failures. Analyst permission is required. The restriction blocks sample portal access for up to five minutes. Request restoration to roll back and verify access in DemoLab.</p>
        <button disabled={!!busy} onClick={()=>void run('Requesting approval…',async()=>{await api(path+'/responses/restrict_test_account',{});setMessage('Approval requested. Review the action in Response Center.')})}>Request approval</button> <Link to="/soc/responses">Open Response Center</Link></>:<p>Review the defensive recommendations with the asset owner and record the analyst decision.</p>}
      <label>Analyst notes<textarea maxLength={1700} value={note} onChange={event=>setNote(event.target.value)}/></label>
      <div className="toolbar">{['Approved recommendation','Rejected recommendation','Marked analyst review completed','Added analyst note'].map((decision,index)=><button key={decision} disabled={!!busy||(index===3&&!note.trim())} onClick={()=>void run('Saving analyst review…',async()=>{
        await api(path+'/notes',{body:'AI review — '+decision+(note.trim()?'\n'+note.trim():'')+(conclusion.trim()?'\nConclusion: '+conclusion.trim():'')})
        setNote('');query.reload();onReview();setMessage(decision+' · recorded in incident notes.')
      })}>{['Approve recommendation','Reject recommendation','Mark review completed','Add analyst note'][index]}</button>)}</div>
      <p>Review decisions are saved as incident notes. Use the Response Center to authorize supported execution.</p></div>}
    </>}
  </section>
}

