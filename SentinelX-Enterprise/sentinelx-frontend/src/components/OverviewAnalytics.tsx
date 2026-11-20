import {useId, useState, type CSSProperties, type ReactNode} from 'react'
import {Activity, Cable, CircleCheck, Clock, Crosshair, Layers, Radar, ShieldAlert, ShieldCheck, Target, TriangleAlert} from 'lucide-react'
import {Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts'
import {label} from '../services/api'
import '../styles/overview.css'

interface Count {name: string; total: number}
interface SeriesPoint {bucket: number; observed: number; simulated: number}
export interface OverviewData {
  totals: Record<string, number>
  series: SeriesPoint[]
  severity: {severity: string; total: number}[]
  response_seconds: number | null
  categories: Count[]
  incident_states: Count[]
  integration_health: Count[]
  alert_trends: {bucket: number; total: number}[]
}

const severityColors: Record<string, string> = {
  critical: '#fb7185', high: '#fb923c', medium: '#fbbf24', low: '#19d878',
}
const statusColors: Record<string, string> = {
  open: '#23a3f5', investigating: '#9759f2', contained: '#fbbf24',
  resolved: '#19d878', closed: '#7995b5',
}
const count = (value: number) => value.toLocaleString()
const time = (bucket: number) => new Date(bucket * 3600000).toLocaleTimeString([], {
  hour: '2-digit', minute: '2-digit', hour12: false,
})
const timestamp = (bucket: number) => new Date(bucket * 3600000).toLocaleString([], {
  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false,
})
const tooltipStyle = {background: '#101d30', border: '1px solid #324965', borderRadius: 10, color: '#eef5ff'}

const metrics = [
  {key: 'events', title: 'Total Events', Icon: ShieldCheck, color: '#16c9fa'},
  {key: 'alerts', title: 'Active Alerts', Icon: TriangleAlert, color: '#ff537c'},
  {key: 'incidents', title: 'Open Incidents', Icon: Layers, color: '#a37aff'},
  {key: 'integrations', title: 'Connected Integrations', Icon: Cable, color: '#15dbc2'},
  {key: 'critical', title: 'Critical Threats', Icon: ShieldAlert, color: '#ff537c'},
  {key: 'assets', title: 'Monitored Assets', Icon: Radar, color: '#3ba9fa'},
  {key: 'resolved', title: 'Resolved Incidents', Icon: CircleCheck, color: '#19d878'},
  {key: 'response', title: 'Avg. Response Time', Icon: Clock, color: '#a37aff'},
]

export function OverviewMetrics({data}: {data: OverviewData}) {
  return <section className="overview-kpis" aria-label="Security metrics">{metrics.map(({key, title, Icon, color}) => {
    const value = key === 'response'
      ? (data.response_seconds === null ? '\u2014' : Math.round(data.response_seconds)+'s')
      : count(data.totals[key])
    const points = key === 'events' && data.series.length > 0
      ? hourlyBuckets(data.series.map(row => row.bucket)).map(bucket => {
          const row = data.series.find(item => item.bucket === bucket)
          return {total: row ? row.observed + row.simulated : 0}
        })
      : undefined
    return <article key={key} className="overview-kpi" style={{'--kpi-accent': color} as CSSProperties}>
      <span className="overview-kpi-icon"><Icon size={20} aria-hidden="true"/></span>
      <div><span>{title}</span><strong>{value}</strong></div>
      {points && <div className="overview-sparkline" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={points}><Area type="monotone" dataKey="total" stroke={color}
            strokeWidth={1.5} fill={color} fillOpacity={.16} isAnimationActive={false}/></AreaChart>
        </ResponsiveContainer>
      </div>}
    </article>
  })}</section>
}

function AnalyticsCard({title, subtitle, icon, accessory, children}: {
  title: string; subtitle: string; icon: ReactNode; accessory?: ReactNode; children: ReactNode
}) {
  return <article className="panel overview-card">
    <header><span className="overview-chart-icon" aria-hidden="true">{icon}</span>
      <div><h2>{title}</h2><p>{subtitle}</p></div>{accessory}
    </header>
    {children}
  </article>
}

function Empty({children}: {children: ReactNode}) {
  return <p className="overview-empty">{children}</p>
}

function hourlyBuckets(buckets: number[]) {
  const end = Math.max(Math.floor(Date.now() / 3600000), ...buckets)
  // The API uses a rolling cutoff, so the earliest hourly bucket can be partial.
  return Array.from({length: 25}, (_, index) => end - 24 + index)
}

function Timeline({series, trends}: {series?: SeriesPoint[]; trends?: OverviewData['alert_trends']}) {
  const id = useId().replace(/[^a-z0-9_-]/gi, '')
  const [small, setSmall] = useState(false)
  const rows = series ?? trends ?? []
  if (!rows.length) return <Empty>{series ? 'No security events in the last 24 hours.' : 'No alerts in the last 24 hours.'}</Empty>
  const byHour = new Map(rows.map(row => [row.bucket, row]))
  const points = hourlyBuckets(rows.map(row => row.bucket)).map(bucket => {
    const row = byHour.get(bucket)
    return {bucket, observed: row && 'observed' in row ? row.observed : 0,
      simulated: row && 'simulated' in row ? row.simulated : 0, total: row && 'total' in row ? row.total : 0}
  })
  const step = small ? 8 : 4
  const ticks = points.filter((_, index) => index % step === 0).map(point => point.bucket)
  return <>
    {series && <div className="overview-key" aria-label="Event series">
      <span><i style={{background: '#38bdf8'}}/>Observed</span>
      <span><i style={{background: '#a78bfa'}}/>Simulated</span>
    </div>}
    <div className={series ? 'overview-timeline' : 'overview-timeline overview-timeline-compact'}>
      <ResponsiveContainer width="100%" height="100%" minWidth={0} onResize={width => setSmall(width < 450)}>
        <AreaChart data={points} margin={{top: 10, right: 22, bottom: 3, left: 0}} accessibilityLayer>
          <defs>
            <linearGradient id={id+'-cyan'} x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity={.34}/><stop offset="100%" stopColor="#38bdf8" stopOpacity={.02}/>
            </linearGradient>
            <linearGradient id={id+'-purple'} x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#a45cff" stopOpacity={.45}/><stop offset="100%" stopColor="#a78bfa" stopOpacity={.03}/>
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#182d49" vertical={false}/>
          <XAxis dataKey="bucket" ticks={ticks} tickFormatter={time} axisLine={false} tickLine={false}
            tick={{fill: '#a4b6cc', fontSize: 11}} tickMargin={10} padding={{left: 14, right: 4}}/>
          <YAxis width={46} tickCount={4} allowDecimals={false} axisLine={false} tickLine={false}
            tick={{fill: '#a4b6cc', fontSize: 11}} tickFormatter={value => Intl.NumberFormat(undefined, {notation: 'compact'}).format(value)}/>
          <Tooltip contentStyle={tooltipStyle} labelStyle={{color: '#d9e8fd'}} labelFormatter={value => typeof value === 'number' ? timestamp(value) : value}
            formatter={value => typeof value === 'number' ? count(value) : value} cursor={{stroke: '#637a99', strokeDasharray: '3 4'}}/>
          {series && <Area type="monotone" dataKey="observed" name="Observed" stroke="#38bdf8" strokeWidth={2}
            fill={'url(#'+id+'-cyan)'} activeDot={{r: 4}} isAnimationActive={false}/>}
          <Area type="monotone" dataKey={series ? 'simulated' : 'total'} name={series ? 'Simulated' : 'Alerts'}
            stroke="#ae65ff" strokeWidth={2.5} fill={'url(#'+id+'-purple)'} activeDot={{r: 4}} isAnimationActive={false}/>
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </>
}

const percent = (value: number, total: number) => new Intl.NumberFormat(undefined, {
  style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1,
}).format(total ? value / total : 0)

function Distribution({rows, colors, center, empty, includeZero = false}: {
  rows: Count[]; colors: Record<string, string>; center: string; empty: string; includeZero?: boolean
}) {
  const source = new Map(rows.map(row => [row.name, row.total]))
  const keys = includeZero ? [...new Set([...Object.keys(colors), ...source.keys()])]
    : [...Object.keys(colors).filter(key => source.has(key)), ...rows.map(row => row.name).filter(key => !(key in colors))]
  const data = keys.map(key => ({
    name: label(key).replace(/^./, char => char.toUpperCase()),
    total: source.get(key) ?? 0, color: colors[key] ?? '#94a3b8',
  }))
  const total = data.reduce((sum, row) => sum + row.total, 0)
  const slices = data.filter(row => row.total > 0)
  return <div className="overview-distribution">
    <div className="overview-donut">
      {total ? <ResponsiveContainer width="100%" height="100%">
        <PieChart accessibilityLayer>
          <Pie data={slices} dataKey="total" nameKey="name" innerRadius="66%" outerRadius="96%"
            startAngle={90} endAngle={-270} stroke="none" isAnimationActive={false}>
            {slices.map(row => <Cell key={row.name} fill={row.color}/>)}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} formatter={value => typeof value === 'number'
            ? count(value)+' ('+percent(value,total)+')' : value}/>
        </PieChart>
      </ResponsiveContainer> : <div className="overview-donut-empty" aria-hidden="true"/>}
      <div className="overview-donut-total"><strong>{count(total)}</strong><span>{center}</span></div>
    </div>
    {total ? <ul className="overview-legend">{data.map(row => <li key={row.name}>
      <i style={{background: row.color}}/><span>{row.name}</span>
      <strong>{count(row.total)} <small>({percent(row.total,total)})</small></strong>
    </li>)}</ul> : <Empty>{empty}</Empty>}
  </div>
}

function CountBars({rows, empty, formatted = true}: {rows: Count[]; empty: string; formatted?: boolean}) {
  const max = Math.max(0, ...rows.map(row => row.total))
  if (!max) return <Empty>{empty}</Empty>
  return <ul className="overview-bars">{[...rows].sort((a,b) => b.total-a.total || a.name.localeCompare(b.name)).map(row =>
    <li key={row.name}><span>{formatted ? label(row.name).replace(/\b[a-z]/g, char => char.toUpperCase()) : row.name}</span>
      <div className="overview-bar-track" aria-hidden="true"><div style={{width: row.total / max * 100+'%'}}/></div>
      <strong>{count(row.total)}</strong>
    </li>)}</ul>
}

export function AnalyticsSkeleton() {
  return <div className="overview-analytics overview-skeleton" role="status">
    <span className="overview-sr-only">Loading dashboard analytics</span>
    {Array.from({length: 4}, (_, index) => <div className="panel overview-card" key={index} aria-hidden="true">
      <span/><span/><div/>
    </div>)}
  </div>
}

export default function OverviewAnalytics({data}: {data: OverviewData}) {
  return <section className="overview-analytics" aria-label="Dashboard analytics">
    <AnalyticsCard title="Security Events Over Time" subtitle="Observed and simulated telemetry" icon={<Activity size={18}/>} accessory={<span className="overview-range">Last 24 Hours</span>}>
      <Timeline series={data.series}/>
    </AnalyticsCard>
    <AnalyticsCard title="Alert Severity" subtitle="Distribution of recorded alerts" icon={<ShieldCheck size={18}/>}>
      <Distribution rows={data.severity.map(row => ({name:row.severity,total:row.total}))} colors={severityColors} center="Total Alerts" empty="No alerts have been recorded." includeZero/>
    </AnalyticsCard>
    <AnalyticsCard title="Event Categories" subtitle="Recorded alerts grouped by detection rule" icon={<Layers size={18}/>}>
      <CountBars rows={data.categories} empty="Detection categories appear after alerts are generated."/>
    </AnalyticsCard>
    <AnalyticsCard title="Incident Status" subtitle="Current status of security incidents" icon={<Target size={18}/>}>
      <Distribution rows={data.incident_states} colors={statusColors} center="Incidents" empty="No incidents have been opened."/>
    </AnalyticsCard>
    <AnalyticsCard title="Alert Trends" subtitle="Hourly alerts generated in the last 24 hours" icon={<Crosshair size={18}/>}>
      <Timeline trends={data.alert_trends}/>
    </AnalyticsCard>
    <AnalyticsCard title="Integration Health" subtitle="Connectors grouped by current state" icon={<Cable size={18}/>}>
      <CountBars rows={data.integration_health} empty="No integrations have been configured." formatted={false}/>
    </AnalyticsCard>
  </section>
}
