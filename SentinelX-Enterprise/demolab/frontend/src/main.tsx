import React,{FormEvent,useEffect,useState} from 'react'
import {createRoot} from 'react-dom/client'
import {Activity,ArrowUpRight,Cable,FlaskConical,KeyRound,Radio,RefreshCw} from 'lucide-react'
import './site.css'

interface Status {connected:boolean; restricted:boolean; account:string; activity:{id:string;kind:string;asset:string;created:number;state:string}[]}
interface Transaction {id:string;counterparty:string;amount_cents:number;status:string}
const scenarios = [
  ['failed-login','Failed sign-in attempts','Five synthetic authentication failures for the designated test account.'],
  ['web-signal','Suspicious request signal','One synthetic event labeled as a suspicious request.'],
  ['request-volume','Unusual request rate','Three synthetic request-volume signals.'],
  ['application-errors','Application error spike','Three synthetic application error records.'],
  ['service-unavailable','Service unavailability','One synthetic availability failure.'],
  ['api-denied','API access denied','Three synthetic API authorization denials.'],
]
async function request<T>(path:string,body?:object):Promise<T> {
  const response=await fetch('/lab/'+path,body===undefined?undefined:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
  const result=await response.json()
  if(!response.ok) throw new Error(typeof result.detail==='string'?result.detail:'Request failed (HTTP '+response.status+')')
  return result
}
function App() {
  const [setup,setSetup]=useState<boolean>(),[status,setStatus]=useState<Status>(),[busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('')
  const [transactions,setTransactions]=useState<Transaction[]>(),[portalMessage,setPortalMessage]=useState('')
  async function refresh() {
    const data=await request<Status>('status')
    setStatus(data)
    if(data.restricted)setTransactions(undefined)
  }
  async function initialize() {
    setSetup((await request<{required:boolean}>('setup')).required)
    try {await refresh()} catch(error) {if(!(error instanceof Error)||error.message!=='Sign in as DemoLab administrator')throw error}
  }
  useEffect(()=>{initialize().catch(error=>setError(error.message))},[])
  async function perform(work:()=>Promise<void>) {
    setBusy(true);setError('');setMessage('')
    try{await work()}catch(error){setError(error instanceof Error?error.message:'Request failed')}finally{setBusy(false)}
  }
  function submit(event:FormEvent<HTMLFormElement>,work:(fields:object)=>Promise<void>) {
    event.preventDefault()
    const form=event.currentTarget
    void perform(async()=>{await work(Object.fromEntries(new FormData(form)));form.reset()})
  }
  return <><header><div className="logo"><FlaskConical size={23}/> SentinelX <strong>DemoLab</strong></div><div className="header-links"><a href={import.meta.env.VITE_ENTERPRISE_URL||'http://127.0.0.1:5174'}>Enterprise <ArrowUpRight size={14}/></a>{status&&<button disabled={busy} onClick={()=>void perform(async()=>{await request('logout',{});setStatus(undefined)})}>Sign out</button>}</div></header>
  <main><div className="caption"><span/> ISOLATED TEST ENVIRONMENT</div><h1>{status?'Security testing console':setup?'Set up DemoLab':'Sign in to DemoLab'}</h1><p className="intro">{status?'Send labeled synthetic telemetry to SentinelX and apply approved actions to the test account.':'DemoLab has its own administrator and stores its activity separately from SentinelX Enterprise.'}</p>
  {error&&<p className="error" role="alert">{error}</p>}{message&&<p className="success" role="status">{message}</p>}
  {status?<><div className="grid summary"><article><Cable/><h2>Enterprise connector</h2><p>{status.connected?'Configured':'Awaiting credentials'}</p></article><article><KeyRound/><h2>Test account</h2><p>{status.account} · {status.restricted?'Restricted':'Available'}</p></article><article><Activity/><h2>Application activity</h2><p>{status.activity.length} recent records</p></article></div>
    <section className="grid settings"><article><h2>Connector configuration</h2><p>Paste the ID and token from Enterprise. Saving sends a verification event.</p><form onSubmit={event=>submit(event,async fields=>{await request('connector',fields);await refresh();setMessage('Verification event delivered. Return to Enterprise to verify the connection.')})}><label>Connector ID<input name="connector" required pattern="[a-f0-9]{32}" autoComplete="off"/></label><label>Connector token<input name="token" type="password" required minLength={43} maxLength={43} autoComplete="off"/></label><button disabled={busy}>Send verification event</button></form></article>
    <article><h2>Approved responses</h2><p>Fetch and apply approved restriction or restoration actions for the designated test account. Restrictions expire after five minutes.</p><div className="actions"><button disabled={busy||!status.connected} onClick={()=>void perform(async()=>{const result=await request<{confirmed:string[]}>('sync',{});await refresh();setMessage(result.confirmed.length?'Recorded response: '+result.confirmed.join(', '):'No approved actions are waiting.')})}><Radio size={16}/> Sync actions</button><button disabled={busy} onClick={()=>void perform(refresh)}><RefreshCw size={16}/> Refresh status</button></div></article></section>
    <section><h2>Sample business portal</h2><article><p>Check whether the designated test account can access its sample transactions.</p><button disabled={busy} onClick={()=>void perform(async()=>{setPortalMessage('');setTransactions(undefined);try{setTransactions((await request<{transactions:Transaction[]}>('sample-portal')).transactions)}catch(error){setPortalMessage(error instanceof Error?error.message:'Portal unavailable')}})}>Check test-account access</button>
      {portalMessage&&<p className="error" role="status">{portalMessage}</p>}{transactions&&<table><thead><tr><th>Transaction</th><th>Counterparty</th><th>Amount</th><th>Status</th></tr></thead><tbody>{transactions.map(row=><tr key={row.id}><td>{row.id}</td><td>{row.counterparty}</td><td>{new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(row.amount_cents/100)}</td><td>{row.status}</td></tr>)}</tbody></table>}</article></section>
    <section><h2>Telemetry scenarios</h2><p>Each run creates up to five records. Wait ten seconds between runs.</p><div className="grid scenarios">{scenarios.map(([key,title,copy])=><article key={key}><h3>{title}</h3><p>{copy}</p><button disabled={busy||!status.connected||(key==='failed-login'&&status.restricted)} onClick={()=>void perform(async()=>{try{const result=await request<{events:unknown[]}>('scenarios/'+key,{});setMessage(result.events.length+' synthetic events delivered.')}finally{await refresh()}})}>Run scenario <ArrowUpRight size={14}/></button></article>)}</div></section>
    <section><h2>Activity history</h2><article className="table">{status.activity.length?<table><thead><tr><th>Signal</th><th>Asset</th><th>Status</th><th>Time</th></tr></thead><tbody>{status.activity.map(row=><tr key={row.id}><td>{row.kind.replaceAll('_',' ')}</td><td>{row.asset}</td><td>{row.state}</td><td>{new Date(row.created*1000).toLocaleString()}</td></tr>)}</tbody></table>:<p>No activity yet.</p>}</article></section></>
    :setup===undefined?<p role="status">Loading…</p>:<article className="login"><form onSubmit={event=>submit(event,async fields=>{await request(setup?'setup':'login',fields);setSetup(false);await refresh()})}><label>Administrator password<input type="password" name="password" minLength={12} maxLength={128} required autoComplete={setup?'new-password':'current-password'}/></label><button disabled={busy}>{busy?'Please wait…':setup?'Create administrator':'Sign in'}</button></form></article>}
  </main></>
}
createRoot(document.getElementById('root')!).render(<App/>)

