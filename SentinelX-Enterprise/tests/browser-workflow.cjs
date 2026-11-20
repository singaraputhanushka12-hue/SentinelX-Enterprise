const assert = require('node:assert/strict')
const {spawn} = require('node:child_process')
const {mkdtempSync} = require('node:fs')
const {createServer} = require('node:net')
const {join, resolve} = require('node:path')

const root = resolve(__dirname, '..')
const {chromium} = require(process.env.SENTINELX_PLAYWRIGHT || join(root,'.deps-browser/node_modules/playwright-core'))
const python = process.env.SENTINELX_TEST_PYTHON || 'python'
const children = []

async function freePort() {
  const socket=createServer()
  await new Promise((accept,reject)=>{socket.once('error',reject);socket.listen(0,'127.0.0.1',accept)})
  const port=socket.address().port
  await new Promise(accept=>socket.close(accept))
  return port
}
function start(executable,args,cwd,changes) {
  const child=spawn(executable,args,{cwd,env:{...process.env,...changes},stdio:['ignore','pipe','pipe'],windowsHide:true})
  child.output=''
  for(const stream of [child.stdout,child.stderr]) stream.on('data', chunk=>{child.output=(child.output+chunk).slice(-12000)})
  child.on('error', error=>{child.output+=error.message})
  children.push(child)
  return child
}
async function ready(address,child) {
  const deadline=Date.now()+30000
  while(Date.now()<deadline && child.exitCode===null){
    try {if ((await fetch(address,{signal:AbortSignal.timeout(750)})).ok) return} catch {}
    await new Promise(accept=>setTimeout(accept,250))
  }
  throw new Error(address+' unavailable\n'+child.output)
}
function backend(module,port,env,args=[]) {
  return start(python,['-B','-m','uvicorn',...args,module,'--host','127.0.0.1','--port',String(port)],root,env)
}
function frontend(folder,port,env) {
  const cwd=join(root,folder)
  const args=['node_modules/vite/bin/vite.js','preview','--host','127.0.0.1','--port',String(port),'--strictPort']
  if(folder==='sentinelx-frontend'&&process.env.SENTINELX_TEST_ENTERPRISE_DIST){
    args.push('--outDir',process.env.SENTINELX_TEST_ENTERPRISE_DIST)
  }
  return start(process.execPath,args,cwd,env)
}
async function run() {
  const ports=new Set()
  while(ports.size<4) ports.add(await freePort())
  const [socPort,labPort,apiPort,labApiPort]=ports
  const url=port=>'http://127.0.0.1:'+port
  const base=mkdtempSync(join(root,'.test-run-'))
  const db=name=>'sqlite:///'+join(base,name+'.sqlite3').replaceAll('\\','/')
  const enterprise=backend('app.main:app',apiPort,{SENTINELX_DATABASE_URL:db('enterprise'),SENTINELX_ORIGINS:url(socPort)},['--app-dir','sentinelx-backend'])
  const demo=backend('demolab.backend.main:app',labApiPort,{DEMOLAB_DATABASE_URL:db('demolab'),DEMOLAB_ORIGINS:url(labPort),DEMOLAB_ENTERPRISE_URL:url(apiPort)})
  await Promise.all([ready(url(apiPort)+'/api/health',enterprise),ready(url(labApiPort)+'/lab/health',demo)])
  const socWeb=frontend('sentinelx-frontend',socPort,{SENTINELX_API:url(apiPort),VITE_DEMOLAB_URL:url(labPort)})
  const labWeb=frontend('demolab/frontend',labPort,{DEMOLAB_API:url(labApiPort),VITE_ENTERPRISE_URL:url(socPort)})
  await Promise.all([ready(url(socPort),socWeb),ready(url(labPort),labWeb)])
  const browser=await chromium.launch({
    channel:process.env.SENTINELX_CHROMIUM_PATH ? undefined : 'chrome',
    executablePath:process.env.SENTINELX_CHROMIUM_PATH,
    headless:true,
    args:['--disable-background-networking']
  })
  try {
    const context=await browser.newContext()
    const soc=await context.newPage()
    const lab=await context.newPage()
    soc.setDefaultTimeout(20000)
    lab.setDefaultTimeout(20000)
    const password='browser-test-password'
    await soc.goto(url(socPort))
    await soc.getByRole('link',{name:'Get Started'}).first().click()
    await soc.getByLabel('Organization name').fill('Browser workflow')
    await soc.getByLabel('Administrator name').fill('Local Analyst')
    await soc.getByLabel('Work email').fill('browser@example.test')
    await soc.getByLabel('Password',{exact:true}).fill(password)
    await soc.getByLabel('Confirm password').fill(password)
    await soc.getByRole('button',{name:'Create organization'}).click()
    await soc.waitForURL('**/onboarding')
    await soc.getByRole('button',{name:'Choose an integration'}).click()
    await soc.getByRole('button',{name:'Continue to configuration'}).click()
    await soc.getByLabel('Integration name').fill('Customer portal')
    await soc.getByRole('button',{name:'Generate credentials'}).click()
    const connector=await soc.getByLabel('Connector ID').inputValue()
    const token=await soc.getByLabel('Connector token').inputValue()
    await soc.getByRole('button',{name:'Verify event ingestion'}).click()
    await soc.getByText('Send an authenticated event within five minutes and try again',{exact:true}).waitFor()
    await lab.goto(url(labPort))
    await lab.getByLabel('Administrator password').fill(password)
    await lab.getByRole('button',{name:'Create administrator'}).click()
    await lab.getByLabel('Connector ID').fill(connector)
    await lab.getByLabel('Connector token').fill(token)
    await lab.getByRole('button',{name:'Send verification event'}).click()
    await lab.getByText('Verification event delivered.',{exact:false}).waitFor()
    await soc.getByRole('button',{name:'Verify event ingestion'}).click()
    await soc.getByRole('button',{name:'Open dashboard'}).click()
    await soc.getByRole('heading',{name:'Security Overview'}).waitFor()
    const sidebar = soc.locator('aside nav')
    assert.equal(await sidebar.getByRole('link',{name:'Threat Intelligence'}).count(),0)
    assert.equal(await sidebar.getByRole('link',{name:'MITRE ATT&CK'}).count(),0)
    for(const path of ['intelligence','mitre']){
      await soc.goto(url(socPort)+'/soc/'+path)
      await soc.waitForURL('**/soc/overview')
      await soc.getByRole('heading',{name:'Security Overview'}).waitFor()
    }
    const remaining = [
      ['Overview','overview'],['Live Monitoring','live'],['Security Alerts','alerts'],
      ['Incidents','incidents'],['AI Investigation','investigation'],['Response Center','responses'],
      ['Integrations','integrations'],['Reports','reports'],['Audit Logs','audit'],['Settings','settings'],
    ]
    for(const [name,path] of remaining){
      await sidebar.getByRole('link',{name,exact:true}).click()
      await soc.waitForURL('**/soc/'+path)
      await soc.locator('main h1').waitFor()
    }

    const scenario=lab.locator('article').filter({has:lab.getByRole('heading',{name:'Failed sign-in attempts'})})
    await scenario.getByRole('button',{name:'Run scenario'}).click()
    await lab.getByText('5 synthetic events delivered.').waitFor()
    await soc.getByRole('link',{name:'Live Monitoring'}).click()
    await soc.getByRole('link',{name:'auth failure'}).first().waitFor()
    await soc.getByRole('link',{name:'Security Alerts'}).click()
    await soc.getByRole('button',{name:'Investigate'}).click()
    await soc.getByText('5 auth failure events were correlated',{exact:false}).waitFor()
    const incidentId = new URL(soc.url()).pathname.split('/').at(-1)
    await sidebar.getByRole('link',{name:'Incidents',exact:true}).click()
    await soc.getByRole('cell',{name:'high',exact:true}).waitFor()
    await soc.getByLabel('Severity',{exact:true}).selectOption('high')
    await soc.getByLabel('Search incidents').fill('does not exist')
    await soc.getByText('No incidents match your filters.').waitFor()
    await soc.getByLabel('Search incidents').fill('Repeated authentication failures')
    await soc.getByRole('link',{name:'Repeated authentication failures',exact:true}).waitFor()
    await sidebar.getByRole('link',{name:'AI Investigation',exact:true}).click()
    await soc.getByLabel('Choose an incident').selectOption(incidentId)
    await soc.waitForURL(url(socPort)+'/soc/investigation?incident='+incidentId)
    const ai=soc.getByRole('region',{name:'AI investigation'})
    await ai.getByText('Current evidence · 5 events',{exact:false}).waitFor()
    assert.equal(await ai.getByRole('button',{name:'Generate Report'}).isDisabled(),true)
    await ai.getByRole('button',{name:'Refresh Evidence'}).click()
    await soc.getByRole('link',{name:'Open incident record'}).click()
    await soc.getByRole('heading',{name:'Supporting events'}).waitFor()
    await soc.getByRole('link',{name:'Open AI Investigation'}).click()
    await soc.waitForURL(url(socPort)+'/soc/investigation?incident='+incidentId)
    assert.equal(await soc.getByLabel('Choose an incident').inputValue(),incidentId)
    await soc.getByRole('link',{name:'Open incident record'}).click()
    for(const [request,result] of [['restriction','Restricted'],['restoration','Available']]) {
      await soc.getByRole('button',{name:request==='restriction'?'Request test-account restriction':'Request account restoration'}).click()
      await soc.getByRole('button',{name:'approve',exact:true}).click()
      await soc.getByText('approved',{exact:true}).waitFor()
      await lab.getByRole('button',{name:'Sync actions'}).click()
      await lab.getByText('demo-test-account · '+result,{exact:true}).waitFor()
      await lab.getByRole('button',{name:'Check test-account access'}).click()
      await lab.getByText(request==='restriction'?'Test account access is temporarily restricted':'DL-1001',{exact:true}).waitFor()
      await soc.getByRole('button',{name:'Refresh status'}).click()
      await soc.getByText(request==='restriction'?'restricted':'restored',{exact:true}).waitFor()
      await soc.getByRole('link',{name:'Open incident'}).first().click()
    }
    await soc.getByLabel('Resolution').fill('Browser verified account restoration.')
    await soc.getByRole('button',{name:'Close incident'}).click()
    await soc.getByText('Browser verified account restoration.',{exact:true}).waitFor()
    assert.match(soc.url(),/\/soc\/incidents\/[^/]+$/)
    console.log('Browser workflow passed through closure and restoration.')
  } finally {
    await browser.close()
  }
}
run().catch(error=>{console.error(error);process.exitCode=1}).finally(()=>{
  for(const child of children) if(child.exitCode===null) child.kill()
})

