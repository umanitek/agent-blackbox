// Agent Blackbox inside Hermes Desktop: a shield in the status bar, a Blackbox section in the
// sidebar with everything the Blackbox dashboard does, and an alert the moment Blackbox flags or
// blocks something an agent tried to do.
//
// Data: Blackbox's own Desktop routes (dashboard/plugin_api.py) through ctx.rest — /status,
// /findings and /mode, and /dash/<route>, which forwards an allowlisted set of the running
// dashboard's own API (desktop/dashboard_link.py), so every panel here shows exactly what the
// dashboard shows. Hermes answers these routes only for this app's own credential. The live alert
// comes from the `plugin.blackbox.finding` event (desktop/__init__.py) and never carries commands
// or evidence. Plain ESM, no build step: Hermes loads this file uncompiled, so UI is written with
// jsx()/jsxs(), and only @hermes/plugin-sdk, react and react/jsx-runtime are imported.

import {
  Badge,
  Button,
  Codicon,
  host,
  queryClient,
  relativeTime,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  useQuery
} from '@hermes/plugin-sdk'
import { useEffect, useMemo, useRef, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const PAGE = '/blackbox'
const POLL_MS = 10000 // the live event refreshes at once; polling covers a dropped connection
const SLOW_POLL_MS = 30000
const STATUS_KEY = ['blackbox', 'status']
const FINDINGS_KEY = ['blackbox', 'findings']
const AUDIT_NOTICE_KEY = 'auditNoticeShown' // ctx.storage: the one-time "recording, not blocking" notice
const TABS = [
  ['overview', 'Overview'],
  ['threats', 'Threats'],
  ['activity', 'Activity'],
  ['graph', 'Threat graph'],
  ['trader', 'Trader Shield'],
  ['agents', 'Agents'],
  ['community', 'Community'],
  ['settings', 'Settings']
]
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']

let rest = null // ctx.rest, set in register() and cleared on dispose

const fetchStatus = () => (rest ? rest('/status') : Promise.resolve({ available: false }))

// The dashboard's own API through Blackbox's Desktop routes. A failure comes back as an object
// with `error` (and `dashboardDown` when the dashboard is not running), never a thrown request.
async function dash(path, opts) {
  if (!rest) return { error: 'Blackbox is not loaded', unavailable: true }
  try {
    const answer = await rest(`/dash/${path}`, opts)
    return answer == null ? {} : answer
  } catch (error) {
    const text = String((error && error.message) || error || '')
    return { error: text, dashboardDown: /dashboard is not running|503/.test(text) }
  }
}

function useDash(key, path, interval) {
  return useQuery({ queryKey: ['blackbox', 'dash', key, path], queryFn: () => dash(path), refetchInterval: interval || SLOW_POLL_MS })
}

const refreshDash = () => queryClient.invalidateQueries({ queryKey: ['blackbox', 'dash'] })
const modeLabel = mode => (mode === 'block' ? 'Block' : 'Audit')
const severityVariant = severity =>
  severity === 'critical' || severity === 'high' ? 'destructive' : severity === 'medium' ? 'warn' : 'muted'
const asList = value => (Array.isArray(value) ? value : [])
const asObject = value => (value && typeof value === 'object' && !Array.isArray(value) ? value : {})
const num = value => (typeof value === 'number' ? value.toLocaleString() : '–')
const when = seconds => (typeof seconds === 'number' && seconds > 0 ? relativeTime(seconds * 1000) : '–')

async function saveSettings(payload, done) {
  const answer = await dash('api/settings', { method: 'POST', body: payload })
  const ok = !!(answer && answer.ok)
  host.notify(
    ok
      ? { kind: 'success', message: done }
      : { kind: 'error', message: `Not saved: ${asList(answer && answer.errors).join('; ') || (answer && answer.error) || 'unknown error'}` }
  )
  refreshDash()
  queryClient.invalidateQueries({ queryKey: STATUS_KEY })
  return ok
}

// The Audit / Block switch. Saved by Blackbox's own checked settings path (POST /mode), never by an agent.
async function setMode(mode) {
  if (!rest) return false
  try {
    const result = await rest('/mode', { method: 'POST', body: { mode } })
    queryClient.invalidateQueries({ queryKey: STATUS_KEY })
    refreshDash()
    if (result && result.ok) {
      host.notify({
        kind: 'success',
        message: mode === 'block' ? 'Blocking is on: Blackbox now stops threats' : 'Audit mode: Blackbox records threats but does not stop them'
      })
      return true
    }
    host.notify({ kind: 'error', message: `Could not change the mode: ${asList(result && result.errors).join('; ') || (result && result.error) || 'unknown error'}` })
  } catch (error) {
    host.notifyError(error, 'Could not change the mode')
  }
  return false
}

// ---------------------------------------------------------------- small building blocks

function Label({ children }) {
  return jsx('div', { className: 'text-[0.65rem] uppercase tracking-wide text-(--ui-text-quaternary)', children })
}

function Fact({ label, value }) {
  return jsxs('div', {
    className: 'flex flex-col gap-0.5',
    children: [jsx(Label, { children: label }), jsx('span', { className: 'text-sm text-(--ui-text-secondary)', children: value })]
  })
}

function Section({ title, help, actions, children }) {
  return jsxs('section', {
    className: 'flex flex-col gap-2 border-t border-(--ui-stroke-secondary) pt-4',
    children: [
      jsxs('div', {
        className: 'flex items-center gap-2',
        children: [
          jsx('h2', { className: 'text-sm font-medium text-(--ui-text-secondary)', children: title }),
          jsx('div', { className: 'flex-1' }),
          actions || null
        ]
      }),
      help ? jsx('p', { className: 'max-w-3xl text-[0.8rem] text-(--ui-text-tertiary)', children: help }) : null,
      children
    ]
  })
}

function Note({ children }) {
  return jsx('div', { className: 'py-3 text-sm text-(--ui-text-tertiary)', children })
}

function DashState({ query, children }) {
  const data = query.data
  if (query.isLoading) return jsx(Note, { children: 'Loading…' })
  if (data && data.dashboardDown) {
    return jsx(Note, {
      children: 'The Blackbox dashboard service is not running, so this panel cannot load. It starts at login; to start it now, run `blackbox dashboard` in a terminal.'
    })
  }
  if (data && data.error && !Array.isArray(data)) return jsx(Note, { children: `Could not load: ${data.error}` })
  return children(data)
}

function Row({ children }) {
  return jsx('div', { className: 'flex flex-wrap items-center gap-2 border-b border-(--ui-stroke-secondary) py-2 text-sm', children })
}

function Grow({ children, title }) {
  return jsx('span', { className: 'min-w-0 flex-1 truncate text-(--ui-text-secondary)', title, children })
}

function Dim({ children }) {
  return jsx('span', { className: 'text-[0.7rem] text-(--ui-text-tertiary)', children })
}

function Checkbox({ checked, onChange, label, disabled }) {
  return jsxs('label', {
    className: 'flex items-center gap-2 text-sm text-(--ui-text-secondary)',
    children: [
      jsx('input', { type: 'checkbox', checked: !!checked, disabled: !!disabled, onChange: event => onChange(event.target.checked) }),
      jsx('span', { children: label })
    ]
  })
}

function SeverityPick({ value, onChange }) {
  return jsx('select', {
    className: 'rounded border border-(--ui-stroke-secondary) bg-transparent px-1 py-0.5 text-sm text-(--ui-text-secondary)',
    value: SEVERITIES.includes(value) ? value : 'info',
    onChange: event => onChange(event.target.value),
    children: SEVERITIES.map(name => jsx('option', { value: name, children: name }, name))
  })
}

function openDashboard(ctx, url) {
  ctx.os.openExternal(url).then(opened => {
    if (!opened) host.notify({ kind: 'warning', message: `Open ${url} in your browser` })
  })
}

// ---------------------------------------------------------------- status bar

function useStatus() {
  return useQuery({ queryKey: STATUS_KEY, queryFn: fetchStatus, refetchInterval: POLL_MS })
}

function StatusChip() {
  const { data } = useStatus()
  const today = (data && data.today) || { findings: 0, blocked: 0 }
  const variant = !data || !data.available ? 'muted' : today.blocked > 0 ? 'destructive' : today.findings > 0 ? 'warn' : 'success'
  const count = data && data.available ? today.findings : null // checked actions with a finding

  return jsxs('button', {
    type: 'button',
    className: 'flex items-center gap-1 px-1.5 text-[0.6875rem] text-(--ui-text-tertiary) hover:text-(--ui-text-secondary)',
    title: data && data.available
      ? `Blackbox: ${data.mode === 'block' ? 'Block mode, stopping threats' : 'Audit mode, recording but not stopping threats'}; ${today.findings} caught today`
      : 'Blackbox',
    onClick: () => host.navigate(PAGE),
    children: [
      jsx(Codicon, { name: 'shield' }),
      data && data.available
        ? jsx(Badge, { size: 'xs', variant: data.mode === 'block' ? 'success' : 'warn', children: modeLabel(data.mode) })
        : jsx('span', { children: 'Blackbox' }),
      count === null ? null : jsx(Badge, { size: 'xs', variant, children: String(count) })
    ]
  })
}

// ---------------------------------------------------------------- Overview

function ModeSwitch({ mode }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const choose = async next => {
    setBusy(true)
    await setMode(next)
    setBusy(false)
    setConfirming(false)
  }
  const option = (value, label) =>
    jsx(Button, {
      size: 'sm',
      variant: mode === value ? 'default' : 'outline',
      disabled: busy || mode === value,
      onClick: () => (value === 'audit' ? setConfirming(true) : choose('block')),
      children: label
    })
  return jsxs('div', {
    className: 'flex flex-col gap-2',
    children: [
      jsxs('div', {
        className: 'flex flex-wrap items-center gap-2',
        children: [jsx(Label, { children: 'Mode' }), option('audit', 'Audit: record only'), option('block', 'Block: stop threats')]
      }),
      confirming
        ? jsxs('div', {
            className: 'flex flex-wrap items-center gap-2 text-sm text-(--ui-text-secondary)',
            children: [
              jsx('span', { children: 'Switch to audit? Blackbox will keep recording threats but will stop blocking them.' }),
              jsx(Button, { size: 'sm', variant: 'destructive', disabled: busy, onClick: () => choose('audit'), children: 'Switch to audit' }),
              jsx(Button, { size: 'sm', variant: 'outline', disabled: busy, onClick: () => setConfirming(false), children: 'Keep blocking' })
            ]
          })
        : null
    ]
  })
}

function FindingRow({ item }) {
  return jsxs(Row, {
    children: [
      jsx(Badge, { variant: item.outcome === 'blocked' ? 'destructive' : 'warn', children: item.outcome }),
      jsx(Badge, { variant: severityVariant(item.severity), children: item.severity }),
      jsx(Grow, { title: item.title, children: item.title }),
      item.more > 0 ? jsx(Badge, { variant: 'outline', children: `+${item.more} more` }) : null,
      jsx(Dim, { children: item.tool }),
      jsx('span', { className: 'w-20 text-right text-[0.7rem] text-(--ui-text-quaternary)', children: item.time ? relativeTime(item.time * 1000) : '' })
    ]
  })
}

function Overview({ status, setTab }) {
  const findings = useQuery({ queryKey: FINDINGS_KEY, queryFn: () => (rest ? rest('/findings') : { findings: [] }), refetchInterval: POLL_MS })
  const sync = useDash('sync', 'api/verified-sync')
  const shields = useDash('shields', 'api/shields')
  const s = status
  const items = asList(findings.data && findings.data.findings).slice(0, 6)
  const trader = asList(shields.data).find(card => card && card.shield_id === 'trader')
  const syncData = asObject(sync.data)
  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsx('p', {
        className: 'max-w-2xl text-sm text-(--ui-text-tertiary)',
        children:
          s.mode === 'block'
            ? `Blackbox checks every tool call and model request before it runs, and refuses those at or above ${s.blockSeverity} severity.`
            : 'Blackbox checks every tool call and model request before it runs, and records what it finds. In audit mode it does not stop anything: turn on Block to have it refuse threats.'
      }),
      jsx(ModeSwitch, { mode: s.mode }),
      jsxs('div', {
        className: 'grid grid-cols-2 gap-4 sm:grid-cols-4',
        children: [
          jsx(Fact, { label: 'Threat rules', value: s.rules != null ? s.rules.toLocaleString() : 'loading' }),
          jsx(Fact, { label: 'Verified graph', value: syncData.phase_text || syncData.state || '–' }),
          jsx(Fact, { label: 'Caught today', value: String(s.today.findings) }),
          jsx(Fact, { label: 'Blocked today', value: String(s.today.blocked) })
        ]
      }),
      trader
        ? jsxs(Row, {
            children: [
              jsx(Codicon, { name: 'shield' }),
              jsx(Grow, { children: `${trader.name}: ${asObject(trader.mode).enabled ? 'engaged' : 'off'}` }),
              jsx(Button, { size: 'sm', variant: 'outline', onClick: () => setTab('trader'), children: asObject(trader.mode).enabled ? 'Open' : 'Set up' })
            ]
          })
        : null,
      jsx(Section, {
        title: 'Recent findings',
        actions: jsx(Button, { size: 'sm', variant: 'outline', onClick: () => setTab('threats'), children: 'All threats' }),
        children:
          items.length === 0
            ? jsx(Note, { children: 'Nothing flagged yet. Blackbox is watching every tool call your agents make.' })
            : items.map((item, index) => jsx(FindingRow, { item }, `${item.time}-${index}`))
      })
    ]
  })
}

// ---------------------------------------------------------------- Threats and Activity

function Threats() {
  const [order, setOrder] = useState('newest')
  const query = useDash('findings', 'api/findings?limit=200', POLL_MS)
  return jsx(Section, {
    title: 'Threats detected',
    help: 'Everything Blackbox flagged or blocked on this machine, with the evidence it recorded (redacted, kept on this machine only).',
    actions: jsxs('div', {
      className: 'flex gap-1',
      children: [
        jsx(Button, { size: 'sm', variant: order === 'newest' ? 'default' : 'outline', onClick: () => setOrder('newest'), children: 'Newest' }),
        jsx(Button, { size: 'sm', variant: order === 'severity' ? 'default' : 'outline', onClick: () => setOrder('severity'), children: 'Most severe' })
      ]
    }),
    children: jsx(DashState, {
      query,
      children: data => {
        const rows = asList(asObject(data).findings).slice()
        if (order === 'severity') rows.sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || (b.ts || 0) - (a.ts || 0))
        if (rows.length === 0) return jsx(Note, { children: 'No threats recorded yet.' })
        return rows.map((row, index) =>
          jsxs(
            Row,
            {
              children: [
                jsx(Badge, { variant: row.decision === 'block' ? 'destructive' : 'warn', children: row.decision === 'block' ? 'blocked' : 'flagged' }),
                jsx(Badge, { variant: severityVariant(row.severity), children: row.severity || 'unknown' }),
                jsx(Grow, { title: `${row.identifier || ''}\n${row.evidence || ''}`, children: row.title || row.identifier }),
                jsx(Dim, { children: row.tool_name || row.event }),
                jsx('span', { className: 'w-20 text-right text-[0.7rem] text-(--ui-text-quaternary)', children: when(row.ts) })
              ]
            },
            `${row.ts}-${index}`
          )
        )
      }
    })
  })
}

function Activity() {
  const query = useDash('audit', 'api/audit?limit=200', POLL_MS)
  return jsx(Section, {
    title: 'Agent activity',
    help: 'What the protected agents did: sessions, tool calls, package installs and file access, newest first.',
    children: jsx(DashState, {
      query,
      children: data => {
        const rows = asList(asObject(data).entries)
        if (rows.length === 0) return jsx(Note, { children: 'No activity recorded yet.' })
        return rows.map((row, index) =>
          jsxs(
            Row,
            {
              children: [
                jsx(Badge, { variant: row.severity ? severityVariant(row.severity) : 'outline', children: row.event || 'event' }),
                jsx(Grow, { children: [row.tool || row.tool_name, row.name && `${row.ecosystem ? row.ecosystem + ':' : ''}${row.name}${row.version ? '@' + row.version : ''}`, row.path].filter(Boolean).join(' · ') || row.event }),
                jsx(Dim, { children: row.framework }),
                jsx('span', { className: 'w-20 text-right text-[0.7rem] text-(--ui-text-quaternary)', children: when(row.ts) })
              ]
            },
            `${row.ts}-${index}`
          )
        )
      }
    })
  })
}

// ---------------------------------------------------------------- Threat graph

// The bubble map — the dashboard's Threat graph ported to Desktop: the same layout (the tier at the
// centre with the Umanitek flag, one hub per threat type, dependencies split into one hub per
// ecosystem, threats around their hub, a "+N more" bubble where a hub holds more than is drawn), the
// same palette, sizes, icons and drawing rules (dashboard/static/index.html: CATS, SEV_COLOR, MINT,
// CAT_ICONS, FLAG_PATHS, graphHubVal, nodeCanvas), and the same feel: a live force layout you can
// watch settle, drag bubbles, scroll to zoom, drag the background to pan, fullscreen.
// A Desktop plugin can load neither the dashboard's script nor its vendored force-graph, so this is a
// second copy of those drawing rules — change them in both places (KNOWN_ISSUES records it).
const LEAVES_PER_TYPE = 40
const ALPHA_DECAY = 0.0228 // d3's default: the layout cools over about 300 frames
const GRAPH_CATEGORIES = {
  dependency: { name: 'Dependency', color: '#F59E0B' },
  injection: { name: 'Prompt injection', color: '#FB7185' },
  escalation: { name: 'Escalation', color: '#EF4444' },
  fileaccess: { name: 'File access', color: '#3B82F6' },
  skill: { name: 'Suspicious skill', color: '#A78BFA' },
  secret: { name: 'Secret exposure', color: '#F97316' },
  ioc: { name: 'IOC', color: '#14B8A6' },
  other: { name: 'Other', color: '#94A3B8' }
}
const SEVERITY_RING = { critical: '#EF4444', high: '#FB7185', medium: '#F59E0B', low: '#3B82F6', info: '#94A3B8' }
const GRAPH_MINT = '#80CA9C'
const GRAPH_ICONS = {
  // dependency — Lucide "package"
  dependency: [
    "M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z",
    "M12 22V12",
    "m3.3 7 7.703 4.734a2 2 0 0 0 1.994 0L20.7 7",
    "m7.5 4.27 9 5.15"
  ],
  // escalation — Lucide "square-terminal"
  escalation: [
    "m7 11 2-2-2-2",
    "M11 13h4",
    "M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"
  ],
  // injection (prompt injection) — Lucide "message-square"
  injection: [
    "M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"
  ],
  // fileaccess (file access) — Lucide "file-text"
  fileaccess: [
    "M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z",
    "M14 2v4a2 2 0 0 0 2 2h4",
    "M10 9H8",
    "M16 13H8",
    "M16 17H8"
  ],
  // skill (suspicious skill) — Lucide "puzzle"
  skill: [
    "M15.39 4.39a1 1 0 0 0 1.68-.474 2.5 2.5 0 1 1 3.014 3.015 1 1 0 0 0-.474 1.68l1.683 1.682a2.414 2.414 0 0 1 0 3.414L19.61 19.39a1 1 0 0 1-1.68-.474 2.5 2.5 0 1 0-3.014 3.015 1 1 0 0 1 .474 1.68l-1.683 1.682a2.414 2.414 0 0 1-3.414 0L8.61 19.61a1 1 0 0 0-1.68.474 2.5 2.5 0 1 1-3.014-3.015 1 1 0 0 0 .474-1.68l-1.683-1.682a2.414 2.414 0 0 1 0-3.414L4.39 8.61a1 1 0 0 1 1.68.474 2.5 2.5 0 1 0 3.014-3.015 1 1 0 0 1-.474-1.68l1.683-1.682a2.414 2.414 0 0 1 3.414 0z"
  ],
  // secret (secret exposure) — Lucide "key-round"
  secret: [
    "M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z",
    "M16.5 7.5h0.01"
  ],
  // other — Lucide "shield-alert"
  other: [
    "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",
    "M12 8v4",
    "M12 16h.01"
  ]
};
const FLAG_PATHS = [
  'M58.192 87.252H65.642L106.328 0H98.879L58.192 87.252Z',
  'M16.292 40.202H77.342L96.085 0H35.045L16.292 40.202Z',
  'M18.753 9.623H28.36L16.267 35.559H18.456L30.549 9.623H47.296L28.544 49.826H0L18.753 9.623Z'
]
const iconCache = new Map()
const iconPaths = type => {
  const key = GRAPH_ICONS[type] ? type : 'other'
  if (!iconCache.has(key)) iconCache.set(key, GRAPH_ICONS[key].map(d => new Path2D(d)))
  return iconCache.get(key)
}
let flagCache = null
const nodeRadius = value => Math.sqrt(Math.max(value || 1, 1)) * 1.9
const hubValue = count => 13 + Math.min(19, Math.log(count + 1) * 3.2)

function darken(hex, factor) {
  const value = String(hex || '#94A3B8').replace('#', '')
  const channel = index => Math.round(parseInt(value.slice(index, index + 2), 16) * factor)
  return `rgb(${channel(0)},${channel(2)},${channel(4)})`
}

// threats: [{identifier, category, severity, name}], totals: {category: n}, ecosystemTotals: {npm: n}
function buildBubbleGraph(centerLabel, threats, totals, ecosystemTotals) {
  const nodes = [{ id: '__center__', kind: 'center', label: centerLabel, total: 0, color: GRAPH_MINT, val: 26 }]
  const links = []
  const add = node => {
    nodes.push(node)
    return nodes.length - 1
  }
  const addLeaves = (hubIndex, type, leaves, total) => {
    const color = GRAPH_CATEGORIES[type].color
    for (const leaf of leaves.slice(0, LEAVES_PER_TYPE)) {
      const index = add({ id: leaf.identifier, kind: 'leaf', type, label: leaf.name || leaf.title || leaf.identifier, severity: leaf.severity, color,
        ring: SEVERITY_RING[leaf.severity] || SEVERITY_RING.info, threat: leaf, val: 5 })
      links.push({ from: hubIndex, to: index, length: 26, kind: 'threat' })
    }
    const hidden = total - Math.min(leaves.length, LEAVES_PER_TYPE)
    if (hidden > 0) {
      const index = add({ id: `${nodes[hubIndex].id}:more`, kind: 'more', type, label: `+${hidden.toLocaleString()} more`, color, val: 4 })
      links.push({ from: hubIndex, to: index, length: 30, kind: 'threat' })
    }
  }
  const byType = new Map()
  for (const threat of threats) {
    const type = GRAPH_CATEGORIES[threat.category] ? threat.category : 'other'
    if (!byType.has(type)) byType.set(type, [])
    const list = byType.get(type)
    if (!list.some(item => item.identifier === threat.identifier)) list.push(threat)
  }
  for (const [type, list] of byType) {
    const total = typeof totals[type] === 'number' ? totals[type] : list.length
    const category = GRAPH_CATEGORIES[type]
    const hubIndex = add({ id: `type:${type}`, kind: 'hub', type, label: category.name, total, color: category.color, val: hubValue(total) })
    nodes[0].total += total
    links.push({ from: 0, to: hubIndex, length: 90, kind: 'hub' })
    const ecosystems = type === 'dependency' ? Object.keys(ecosystemTotals || {}) : []
    if (ecosystems.length > 1) {
      // Dependencies span ecosystems: one hub per ecosystem, as the dashboard draws them.
      const byEcosystem = new Map()
      for (const leaf of list) {
        const ecosystem = String(leaf.identifier || '').split(':')[1] || 'other'
        if (!byEcosystem.has(ecosystem)) byEcosystem.set(ecosystem, [])
        byEcosystem.get(ecosystem).push(leaf)
      }
      ecosystems.sort((a, b) => (ecosystemTotals[b] || 0) - (ecosystemTotals[a] || 0))
      for (const ecosystem of ecosystems) {
        const ecosystemTotal = ecosystemTotals[ecosystem] || 0
        const ecosystemIndex = add({ id: `eco:${ecosystem}`, kind: 'hub', type, label: ecosystem, total: ecosystemTotal, color: category.color, val: hubValue(ecosystemTotal) * 0.8 })
        links.push({ from: hubIndex, to: ecosystemIndex, length: 64, kind: 'hub' })
        addLeaves(ecosystemIndex, type, byEcosystem.get(ecosystem) || [], ecosystemTotal)
      }
    } else {
      addLeaves(hubIndex, type, list, total)
    }
  }
  for (const node of nodes) node.r = nodeRadius(node.val)
  return { nodes, links }
}

function themeColor(element, name, fallback) {
  const value = getComputedStyle(element).getPropertyValue(name).trim()
  return value || fallback
}

function seedLayout(nodes, links) {
  nodes[0].x = 0
  nodes[0].y = 0
  const placed = new Set([0])
  const queue = [0]
  while (queue.length) {
    const parent = queue.shift()
    const children = links.filter(link => link.from === parent && !placed.has(link.to))
    children.forEach((link, index) => {
      const angle = (index / Math.max(1, children.length)) * Math.PI * 2 + parent
      const child = nodes[link.to]
      child.x = nodes[parent].x + Math.cos(angle) * link.length
      child.y = nodes[parent].y + Math.sin(angle) * link.length
      placed.add(link.to)
      queue.push(link.to)
    })
  }
  for (const node of nodes) {
    node.vx = 0
    node.vy = 0
  }
}

// One step of the force layout at temperature alpha: charge between nearby bubbles, springs along
// links, velocity decay 0.3 (the dashboard's d3VelocityDecay). A dragged node stays under the pointer.
function stepLayout(nodes, links, alpha) {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i]
      const b = nodes[j]
      const dx = b.x - a.x
      const dy = b.y - a.y
      const distanceSquared = Math.max(dx * dx + dy * dy, 1)
      if (distanceSquared > 90000) continue
      const strength = a.kind === 'leaf' && b.kind === 'leaf' ? 14 : 45
      const push = (alpha * strength) / distanceSquared
      a.vx -= dx * push
      a.vy -= dy * push
      b.vx += dx * push
      b.vy += dy * push
    }
  }
  for (const link of links) {
    const a = nodes[link.from]
    const b = nodes[link.to]
    const dx = b.x - a.x
    const dy = b.y - a.y
    const distance = Math.max(1, Math.hypot(dx, dy))
    const pull = ((distance - link.length) / distance) * alpha * 0.5
    a.vx += dx * pull * 0.3
    a.vy += dy * pull * 0.3
    b.vx -= dx * pull
    b.vy -= dy * pull
  }
  for (const node of nodes) {
    if (node.fixed) {
      node.vx = 0
      node.vy = 0
      continue
    }
    if (node.kind === 'center') {
      node.vx -= node.x * 0.02 * alpha
      node.vy -= node.y * 0.02 * alpha
    }
    node.vx *= 0.7
    node.vy *= 0.7
    node.x += node.vx
    node.y += node.vy
  }
}

function drawIcon(context, type, node, color, k) {
  const box = node.r * 1.55
  context.save()
  context.translate(node.x, node.y)
  context.scale(box / 24, box / 24)
  context.translate(-12, -12)
  context.lineWidth = 1.9
  context.lineJoin = 'round'
  context.lineCap = 'round'
  context.strokeStyle = color
  for (const path of iconPaths(type)) context.stroke(path)
  context.restore()
}

function drawFlag(context, node) {
  if (!flagCache) flagCache = FLAG_PATHS.map(d => new Path2D(d))
  const scale = node.r / 62
  context.save()
  context.beginPath()
  context.arc(node.x, node.y, node.r, 0, Math.PI * 2)
  context.clip()
  context.translate(node.x, node.y)
  context.scale(scale, scale)
  context.translate(-100, -100)
  context.translate(46, 56)
  context.fillStyle = '#ffffff'
  for (const path of flagCache) context.fill(path)
  context.restore()
}

const truncate = (text, size) => (text.length > size ? `${text.slice(0, size - 1)}…` : text)

function drawGraph(canvas, nodes, links, view, hover, theme) {
  const context = canvas.getContext('2d')
  const scale = window.devicePixelRatio || 1
  const width = canvas.width / scale
  const height = canvas.height / scale
  context.setTransform(1, 0, 0, 1, 0, 0)
  context.clearRect(0, 0, canvas.width, canvas.height)
  const k = view.k
  // the grid, in world space so it pans and zooms with the graph
  context.setTransform(scale, 0, 0, scale, 0, 0)
  context.strokeStyle = theme.grid
  context.lineWidth = 1
  const step = 40 * k
  if (step > 8) {
    context.beginPath()
    for (let x = ((view.x % step) + step) % step; x < width; x += step) {
      context.moveTo(x, 0)
      context.lineTo(x, height)
    }
    for (let y = ((view.y % step) + step) % step; y < height; y += step) {
      context.moveTo(0, y)
      context.lineTo(width, y)
    }
    context.stroke()
  }
  context.setTransform(scale * k, 0, 0, scale * k, scale * view.x, scale * view.y)
  for (const link of links) {
    const a = nodes[link.from]
    const b = nodes[link.to]
    context.strokeStyle = link.kind === 'hub' ? 'rgba(128,202,156,0.35)' : 'rgba(160,160,160,0.22)'
    context.lineWidth = (link.kind === 'hub' ? 1.4 : 0.8) / k
    context.beginPath()
    context.moveTo(a.x, a.y)
    context.lineTo(b.x, b.y)
    context.stroke()
  }
  for (const node of nodes) {
    const r = node.r
    if (node.kind === 'hub') {
      context.save()
      context.globalAlpha = 0.22
      context.shadowColor = node.color
      context.shadowBlur = 22 / Math.max(k, 0.7)
      context.fillStyle = node.color
      context.beginPath()
      context.arc(node.x, node.y, r * 1.22, 0, Math.PI * 2)
      context.fill()
      context.restore()
    }
    context.fillStyle = node.kind === 'center' ? '#000000' : node.kind === 'more' ? theme.more : node.color
    context.beginPath()
    context.arc(node.x, node.y, r, 0, Math.PI * 2)
    context.fill()
    if (node.kind === 'center') drawFlag(context, node)
    else if (node.kind === 'hub') drawIcon(context, node.type, node, '#0D0D0D', k)
    else if (node.kind === 'leaf' && k >= 1.4) drawIcon(context, node.type, node, darken(node.color, 0.42), k)
    if (node.kind === 'leaf') {
      context.lineWidth = (hover === node ? 2.4 : 1.6) / k
      context.strokeStyle = node.ring
      context.beginPath()
      context.arc(node.x, node.y, r + 2.2 / k, 0, Math.PI * 2)
      context.stroke()
    } else if (node.kind === 'center') {
      context.lineWidth = 1.8 / k
      context.strokeStyle = GRAPH_MINT
      context.beginPath()
      context.arc(node.x, node.y, r + 1.6 / k, 0, Math.PI * 2)
      context.stroke()
    } else if (node.kind === 'hub') {
      context.lineWidth = 1.2 / k
      context.strokeStyle = theme.outline
      context.beginPath()
      context.arc(node.x, node.y, r, 0, Math.PI * 2)
      context.stroke()
      context.save()
      context.globalAlpha = 0.48
      context.lineWidth = 0.9 / k
      context.strokeStyle = node.color
      context.setLineDash([2.2 / k, 3.2 / k])
      context.beginPath()
      context.arc(node.x, node.y, r + 4.3 / k, 0, Math.PI * 2)
      context.stroke()
      context.restore()
    } else {
      context.lineWidth = 1 / k
      context.strokeStyle = theme.outline
      context.beginPath()
      context.arc(node.x, node.y, r, 0, Math.PI * 2)
      context.stroke()
    }
  }
  context.textAlign = 'center'
  context.textBaseline = 'top'
  const showLeafLabels = k >= 1.6
  for (const node of nodes) {
    const isLeaf = node.kind === 'leaf'
    if (isLeaf && !showLeafLabels && hover !== node) continue
    context.font = `${isLeaf ? 500 : 600} ${(isLeaf ? 9.5 : 11) / k}px system-ui, sans-serif`
    context.fillStyle = node.kind === 'more' ? theme.muted : theme.label
    context.fillText(isLeaf ? truncate(node.label, 28) : node.label, node.x, node.y + node.r + 4 / k)
    if (node.kind === 'hub' || node.kind === 'center') {
      context.font = `600 ${9.5 / k}px ui-monospace, monospace`
      context.fillStyle = node.color
      context.fillText(`${node.total.toLocaleString()} THREATS`, node.x, node.y + node.r + 17 / k)
    }
  }
}

function fitView(nodes, width, height) {
  let minX = Infinity
  let minY = Infinity
  let maxX = -Infinity
  let maxY = -Infinity
  for (const node of nodes) {
    minX = Math.min(minX, node.x - node.r)
    minY = Math.min(minY, node.y - node.r)
    maxX = Math.max(maxX, node.x + node.r)
    maxY = Math.max(maxY, node.y + node.r + 28)
  }
  const pad = 42
  const k = Math.min((width - pad * 2) / Math.max(1, maxX - minX), (height - pad * 2) / Math.max(1, maxY - minY), 4)
  return { k, x: width / 2 - ((minX + maxX) / 2) * k, y: height / 2 - ((minY + maxY) / 2) * k }
}

function BubbleMap({ graph, onPick }) {
  const wrapRef = useRef(null)
  const canvasRef = useRef(null)
  const [hover, setHover] = useState(null)
  const live = useRef({ nodes: [], links: [], view: { k: 1, x: 0, y: 0 }, hover: null, pointer: null, alpha: 1, wake: null, fitted: false })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined
    const state = live.current
    const nodes = graph.nodes.map(node => ({ ...node }))
    seedLayout(nodes, graph.links)
    state.nodes = nodes
    state.links = graph.links
    state.alpha = 1
    state.fitted = false
    const theme = {
      label: themeColor(canvas, '--ui-text-secondary', '#F1EFE9'),
      muted: themeColor(canvas, '--ui-text-tertiary', '#A8A49D'),
      outline: 'rgba(255,255,255,0.20)',
      more: 'rgba(255,255,255,0.05)',
      grid: 'rgba(128,128,128,0.08)'
    }
    let frame = 0
    let ticks = 0
    const size = () => canvas.getBoundingClientRect()
    const loop = () => {
      frame = 0
      if (state.alpha > 0.004) {
        stepLayout(state.nodes, state.links, state.alpha)
        state.alpha *= 1 - ALPHA_DECAY
        ticks++
        if (!state.fitted && ticks > 90) {
          const box = size()
          state.view = fitView(state.nodes, box.width, box.height)
          state.fitted = true
        }
      }
      drawGraph(canvas, state.nodes, state.links, state.view, state.hover, theme)
      if (state.alpha > 0.004 || state.pointer) frame = requestAnimationFrame(loop)
    }
    const wake = () => {
      if (!frame) frame = requestAnimationFrame(loop)
    }
    state.wake = wake
    const resize = () => {
      const box = size()
      const scale = window.devicePixelRatio || 1
      canvas.width = Math.max(1, Math.floor(box.width * scale))
      canvas.height = Math.max(1, Math.floor(box.height * scale))
      state.view = fitView(state.nodes, box.width, box.height)
      wake()
    }
    const observer = new ResizeObserver(resize)
    observer.observe(canvas)
    resize()
    return () => {
      if (frame) cancelAnimationFrame(frame)
      observer.disconnect()
      state.wake = null
    }
  }, [graph])

  const local = event => {
    const box = canvasRef.current.getBoundingClientRect()
    return { x: event.clientX - box.left, y: event.clientY - box.top }
  }
  const toWorld = point => {
    const view = live.current.view
    return { x: (point.x - view.x) / view.k, y: (point.y - view.y) / view.k }
  }
  const nodeAt = point => {
    const world = toWorld(point)
    const slack = 3 / live.current.view.k
    let best = null
    for (const node of live.current.nodes) {
      if (Math.hypot(node.x - world.x, node.y - world.y) <= node.r + slack && (!best || node.kind === 'leaf')) best = node
    }
    return best
  }
  const wake = () => live.current.wake && live.current.wake()
  const toggleFullscreen = () => {
    const wrap = wrapRef.current
    if (!wrap) return
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {})
    else if (wrap.requestFullscreen) wrap.requestFullscreen().catch(() => {})
  }

  return jsxs('div', {
    ref: wrapRef,
    className: 'relative overflow-hidden rounded border border-(--ui-stroke-secondary) bg-(--ui-bg-primary)',
    children: [
      jsx('canvas', {
        ref: canvasRef,
        className: 'block h-[560px] w-full',
        onWheel: event => {
          const point = local(event)
          const view = live.current.view
          const k = Math.min(12, Math.max(0.2, view.k * Math.exp(-event.deltaY * 0.0015)))
          live.current.view = { k, x: point.x - ((point.x - view.x) * k) / view.k, y: point.y - ((point.y - view.y) * k) / view.k }
          live.current.fitted = true
          wake()
        },
        onMouseDown: event => {
          const point = local(event)
          const node = nodeAt(point)
          live.current.pointer = { start: point, view: live.current.view, node, moved: false }
          if (node) node.fixed = true
          wake()
        },
        onMouseMove: event => {
          const point = local(event)
          const pointer = live.current.pointer
          if (pointer) {
            if (Math.abs(point.x - pointer.start.x) + Math.abs(point.y - pointer.start.y) > 3) pointer.moved = true
            if (pointer.node) {
              // drag a bubble: it follows the pointer and the layout around it wakes up
              const world = toWorld(point)
              pointer.node.x = world.x
              pointer.node.y = world.y
              live.current.alpha = Math.max(live.current.alpha, 0.3)
            } else {
              live.current.view = { ...pointer.view, x: pointer.view.x + point.x - pointer.start.x, y: pointer.view.y + point.y - pointer.start.y }
              live.current.fitted = true
            }
            wake()
            return
          }
          const node = nodeAt(point)
          event.currentTarget.style.cursor = node ? (node.kind === 'leaf' ? 'pointer' : 'grab') : 'default'
          if (live.current.hover !== node) {
            live.current.hover = node
            setHover(node && node.kind === 'leaf' ? node : null)
            wake()
          }
        },
        onMouseUp: () => {
          const pointer = live.current.pointer
          live.current.pointer = null
          if (!pointer) return
          if (pointer.node) pointer.node.fixed = false
          if (!pointer.moved && pointer.node && pointer.node.kind === 'leaf') onPick(pointer.node.threat)
          wake()
        },
        onMouseLeave: () => {
          const pointer = live.current.pointer
          if (pointer && pointer.node) pointer.node.fixed = false
          live.current.pointer = null
          live.current.hover = null
          setHover(null)
          wake()
        }
      }),
      hover
        ? jsxs('div', {
            className: 'pointer-events-none absolute left-3 top-3 max-w-sm rounded border border-(--ui-stroke-secondary) bg-(--ui-bg-quaternary) px-2.5 py-1.5 text-[0.75rem] text-(--ui-text-secondary)',
            children: [
              jsx('div', { className: 'font-medium', children: hover.label }),
              jsx('div', { className: 'text-(--ui-text-tertiary)', children: `${hover.severity || 'unknown'} · ${GRAPH_CATEGORIES[hover.type] ? GRAPH_CATEGORIES[hover.type].name : 'Other'}${hover.threat.count > 1 ? ` · seen ${hover.threat.count}×` : ''}` })
            ]
          })
        : null,
      jsx('div', { className: 'pointer-events-none absolute bottom-2 left-3 text-[0.65rem] text-(--ui-text-quaternary)', children: 'Scroll to zoom · drag a bubble or the background · click a threat to open it' }),
      jsx(Button, { size: 'sm', variant: 'outline', className: 'absolute bottom-2 right-2', onClick: toggleFullscreen, children: jsx(Codicon, { name: 'screen-full' }) })
    ]
  })
}

function localThreats(rows) {
  const byIdentifier = new Map()
  for (const row of rows) {
    const key = row.identifier || row.title
    const seen = byIdentifier.get(key)
    if (seen) seen.count += 1
    else byIdentifier.set(key, { identifier: key, category: row.category, severity: row.severity, name: row.title, count: 1, local: true })
  }
  return Array.from(byIdentifier.values())
}

function ThreatDetail({ identifier, tier, onClose }) {
  const query = useDash('threat', `api/threat?identifier=${encodeURIComponent(identifier)}&tier=${encodeURIComponent(tier || 'public')}`)
  return jsx(Section, {
    title: 'Threat',
    actions: jsx(Button, { size: 'sm', variant: 'outline', onClick: onClose, children: 'Back' }),
    children: jsx(DashState, {
      query,
      children: data => {
        const threat = asObject(data)
        if (!threat.found) return jsx(Note, { children: 'This threat is not in the graph on this node.' })
        return jsxs('div', {
          className: 'flex flex-col gap-2 text-sm text-(--ui-text-secondary)',
          children: [
            jsxs('div', {
              className: 'flex flex-wrap items-center gap-2',
              children: [
                jsx(Badge, { variant: severityVariant(threat.severity), children: threat.severity }),
                jsx(Badge, { variant: 'outline', children: threat.category }),
                jsx('span', { className: 'font-medium', children: threat.name || threat.identifier })
              ]
            }),
            threat.description ? jsx('p', { className: 'max-w-3xl text-(--ui-text-tertiary)', children: threat.description }) : null,
            jsx(Dim, { children: threat.identifier }),
            asList(threat.sources).length ? jsx(Fact, { label: 'Sources', value: asList(threat.sources).join(' · ') }) : null,
            asList(threat.references).length ? jsx(Fact, { label: 'References', value: asList(threat.references).join(' · ') }) : null
          ]
        })
      }
    })
  })
}

function ThreatGraph() {
  const [tier, setTier] = useState('public')
  const [category, setCategory] = useState('')
  const [search, setSearch] = useState('')
  const [term, setTerm] = useState('')
  const [open, setOpen] = useState(null)
  const status = useDash('graph-status', 'api/graph-status')
  const sync = useDash('sync', 'api/verified-sync', POLL_MS)
  // A sample of each threat type, asked for separately: the graph lists one type after another, so a
  // single page of the verified tier held no indicators at all (717,005 of them, 2026-11-06).
  const map = useQuery({
    queryKey: ['blackbox', 'dash', 'graph-map', tier],
    refetchInterval: SLOW_POLL_MS,
    queryFn: async () => {
      if (tier === 'local') return dash('api/findings?limit=500')
      const first = await dash(`api/graph?tier=${tier}&limit=${LEAVES_PER_TYPE}`)
      const totals = asObject(asObject(first).category_totals)
      const types = Object.keys(totals).filter(type => totals[type] > 0)
      if (types.length === 0) return first
      const ecosystems = Object.keys(asObject(asObject(first).ecosystem_totals))
      const pages = await Promise.all([
        ...types.filter(type => type !== 'dependency' || ecosystems.length < 2)
          .map(type => dash(`api/graph?tier=${tier}&limit=${LEAVES_PER_TYPE}&category=${encodeURIComponent(type)}`)),
        ...(types.includes('dependency') && ecosystems.length > 1
          ? ecosystems.map(ecosystem => dash(`api/graph?tier=${tier}&limit=${LEAVES_PER_TYPE}&category=dependency&ecosystem=${encodeURIComponent(ecosystem)}`))
          : [])
      ])
      return { ...asObject(first), threats: pages.flatMap(page => asList(asObject(page).threats)) }
    }
  })
  const browse = useDash('graph', `api/graph?tier=public&limit=50&q=${encodeURIComponent(term)}&category=${encodeURIComponent(category)}`)
  const syncNow = async () => {
    const answer = await dash('api/sync', { method: 'POST', body: {} })
    host.notify(answer && answer.ok ? { kind: 'success', message: answer.busy ? 'A sync is already running' : 'Sync started' } : { kind: 'error', message: 'Could not start a sync' })
    refreshDash()
  }
  const mapData = asObject(map.data)
  const tierLabel = { public: 'Verified', community: 'Community', local: 'Local' }[tier]
  const graph = useMemo(() => {
    const threats = tier === 'local' ? localThreats(asList(mapData.findings)) : asList(mapData.threats).map(threat => ({ ...threat, tier }))
    const totals = tier === 'local' ? {} : asObject(mapData.category_totals)
    const ecosystemTotals = tier === 'local' ? {} : asObject(mapData.ecosystem_totals)
    return threats.length ? buildBubbleGraph(tierLabel === 'Verified' ? 'Verifiable graph' : `${tierLabel} graph`, threats, totals, ecosystemTotals) : null
  }, [map.dataUpdatedAt, tier])
  if (open) {
    if (open.local) {
      return jsx(Section, {
        title: open.name || open.identifier,
        actions: jsx(Button, { size: 'sm', variant: 'outline', onClick: () => setOpen(null), children: 'Back' }),
        children: jsxs('div', {
          className: 'flex flex-col gap-1 text-sm text-(--ui-text-secondary)',
          children: [
            jsx(Badge, { variant: severityVariant(open.severity), children: open.severity }),
            jsx(Dim, { children: open.identifier }),
            jsx(Dim, { children: `Seen ${open.count} time(s) on this machine — see the Threats tab for each one.` })
          ]
        })
      })
    }
    return jsx(ThreatDetail, { identifier: open.identifier, tier: open.tier || 'public', onClose: () => setOpen(null) })
  }
  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsx(Section, {
        title: 'Where threat knowledge comes from',
        actions: jsx(Button, { size: 'sm', variant: 'outline', onClick: syncNow, children: 'Sync now' }),
        children: jsx(DashState, {
          query: status,
          children: data => {
            const g = asObject(data)
            const progress = asObject(g.sync_progress)
            const v = asObject(sync.data)
            return jsxs('div', {
              className: 'grid grid-cols-1 gap-4 sm:grid-cols-3',
              children: [
                jsx(Fact, { label: 'Verified (may block)', value: `${num(g.curated)} rules · ${asObject(progress.public).label || v.phase_text || ''}` }),
                jsx(Fact, { label: 'Community (flags only)', value: `${num(g.community)} · ${asObject(progress.community).label || ''}` }),
                jsx(Fact, { label: 'Local (this machine)', value: `${num(g.findings_logged)} findings` }),
                jsx(Fact, { label: 'DKG node', value: g.node_reachable ? 'running' : 'not answering' }),
                jsx(Fact, { label: 'Verified sync', value: typeof v.percent_compiled === 'number' ? `${Math.round(v.percent_compiled)}% compiled · ${num(v.verified_rules)} rules` : v.state || '–' }),
                jsx(Fact, { label: 'Last sync', value: when(g.last_sync) })
              ]
            })
          }
        })
      }),
      jsx(Section, {
        title: 'Threat graph',
        help: 'Each bubble is a threat, grouped by type and coloured by severity. Hover to see it, click to open it. A sample of at most 40 per type is drawn; search below to find any threat.',
        actions: jsx('div', {
          className: 'flex gap-1',
          children: [['public', 'Verified'], ['community', 'Community'], ['local', 'Local']].map(([id, label]) =>
            jsx(Button, { size: 'sm', variant: tier === id ? 'default' : 'outline', onClick: () => setTier(id), children: label }, id)
          )
        }),
        children: jsx(DashState, {
          query: map,
          children: () =>
            graph
              ? jsx(BubbleMap, { graph, onPick: threat => setOpen(threat) })
              : jsx(Note, { children: `No ${tierLabel.toLowerCase()} threats to draw yet.` })
        })
      }),
      jsx(Section, {
        title: 'Search the verified graph',
        children: jsxs('div', {
          className: 'flex flex-col gap-2',
          children: [
            jsxs('form', {
              className: 'flex flex-wrap items-center gap-2',
              onSubmit: event => {
                event.preventDefault()
                setTerm(search.trim())
              },
              children: [
                jsx('input', {
                  className: 'min-w-0 flex-1 rounded border border-(--ui-stroke-secondary) bg-transparent px-2 py-1 text-sm text-(--ui-text-secondary)',
                  placeholder: 'Search a package, domain, wallet or pattern',
                  value: search,
                  onChange: event => setSearch(event.target.value)
                }),
                jsx('select', {
                  className: 'rounded border border-(--ui-stroke-secondary) bg-transparent px-1 py-1 text-sm text-(--ui-text-secondary)',
                  value: category,
                  onChange: event => setCategory(event.target.value),
                  children: [['', 'All kinds'], ['dependency', 'Packages'], ['ioc', 'Indicators'], ['injection', 'Prompt injection'], ['skill', 'Skills']].map(([value, label]) =>
                    jsx('option', { value, children: label }, value)
                  )
                }),
                jsx(Button, { size: 'sm', type: 'submit', children: 'Search' })
              ]
            }),
            jsx(DashState, {
              query: browse,
              children: data => {
                const page = asObject(data)
                const rows = asList(page.threats)
                const pageTotals = asObject(page.category_totals)
                return jsxs('div', {
                  className: 'flex flex-col',
                  children: [
                    jsx(Dim, { children: `${num(page.total)} threats${Object.keys(pageTotals).length ? ' · ' + Object.entries(pageTotals).map(([k, v]) => `${k} ${num(v)}`).join(' · ') : ''}` }),
                    rows.length === 0
                      ? jsx(Note, { children: 'No match.' })
                      : rows.map(threat =>
                          jsxs(
                            'button',
                            {
                              type: 'button',
                              className: 'flex items-center gap-2 border-b border-(--ui-stroke-secondary) py-2 text-left text-sm hover:bg-(--chrome-action-hover)',
                              onClick: () => setOpen({ ...threat, tier: 'public' }),
                              children: [
                                jsx(Badge, { variant: severityVariant(threat.severity), children: threat.severity }),
                                jsx(Badge, { variant: 'outline', children: threat.category }),
                                jsx(Grow, { children: threat.name || threat.identifier })
                              ]
                            },
                            threat.identifier
                          )
                        )
                  ]
                })
              }
            })
          ]
        })
      })
    ]
  })
}

// ---------------------------------------------------------------- Trader Shield (and any other shield)

function ShieldSettings({ shieldId, section }) {
  const mode = asObject(section.mode)
  const [draft, setDraft] = useState(null)
  const value = draft || { enabled: !!mode.enabled, wallets: asList(mode.wallets), addresses: asList(mode.addresses) }
  const fields = asList(section.fields)
  const change = (key, next) => setDraft({ ...value, [key]: next })
  const save = async () => {
    const ok = await saveSettings({ shields: { [shieldId]: value } }, 'Trader Shield settings saved. Restart your agent so it picks them up.')
    if (ok) setDraft(null)
  }
  return jsxs('div', {
    className: 'flex flex-col gap-3',
    children: [
      ...fields.map(field => {
        if (field.kind === 'toggle') {
          return jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx(Checkbox, { checked: value[field.key], onChange: next => change(field.key, next), label: field.label }),
              field.help ? jsx('p', { className: 'max-w-3xl text-[0.75rem] text-(--ui-text-tertiary)', children: field.help }) : null
            ]
          }, field.key)
        }
        if (field.kind === 'multi-pick') {
          const chosen = new Set(asList(value[field.key]))
          return jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx(Label, { children: field.label }),
              jsx('div', {
                className: 'flex flex-wrap gap-x-4 gap-y-1',
                children: asList(field.options).map(option =>
                  jsx(
                    Checkbox,
                    {
                      checked: chosen.has(option.id),
                      label: option.name + (option.status && option.status !== 'supported' ? ` (${option.status})` : ''),
                      onChange: next => {
                        const updated = new Set(chosen)
                        if (next) updated.add(option.id)
                        else updated.delete(option.id)
                        change(field.key, Array.from(updated))
                      }
                    },
                    option.id
                  )
                )
              })
            ]
          }, field.key)
        }
        if (field.kind === 'lines') {
          return jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx(Label, { children: field.label }),
              field.help ? jsx('p', { className: 'max-w-3xl text-[0.75rem] text-(--ui-text-tertiary)', children: field.help }) : null,
              jsx('textarea', {
                className: 'min-h-16 rounded border border-(--ui-stroke-secondary) bg-transparent p-2 font-mono text-[0.75rem] text-(--ui-text-secondary)',
                value: asList(value[field.key]).join('\n'),
                onChange: event => change(field.key, event.target.value.split('\n').map(line => line.trim()).filter(Boolean))
              })
            ]
          }, field.key)
        }
        return null
      }),
      jsxs('div', {
        className: 'flex gap-2',
        children: [
          jsx(Button, { size: 'sm', disabled: !draft, onClick: save, children: 'Save' }),
          draft ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => setDraft(null), children: 'Discard changes' }) : null
        ]
      })
    ]
  })
}

function TraderShield({ ctx, dashboardUrl }) {
  const cards = useDash('shields', 'api/shields')
  const settings = useDash('settings', 'api/settings')
  const events = useDash('trader-events', 'api/shields/trader/events', POLL_MS)
  return jsx(DashState, {
    query: cards,
    children: data => {
      const card = asList(data).find(item => item && item.shield_id === 'trader')
      if (!card) return jsx(Note, { children: 'Trader Shield is not available in this version.' })
      const section = asObject(asObject(asObject(settings.data).shields).trader)
      const eventRows = asList(events.data)
      return jsxs('div', {
        className: 'flex flex-col gap-4',
        children: [
          jsxs('div', {
            className: 'flex flex-wrap items-center gap-2',
            children: [
              jsx('h2', { className: 'text-base font-medium text-(--ui-text-secondary)', children: card.name }),
              card.beta ? jsx(Badge, { variant: 'outline', children: 'Beta' }) : null,
              jsx(Badge, { variant: asObject(card.mode).enabled ? (card.blocking ? 'success' : 'warn') : 'muted', children: asObject(card.mode).enabled ? (card.blocking ? 'Engaged · blocking' : 'Engaged · audit only') : 'Off' }),
              jsx('div', { className: 'flex-1' }),
              card.page ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => openDashboard(ctx, String(dashboardUrl || 'http://127.0.0.1:9700/').replace(/\/$/, '') + card.page), children: 'Tested attacks' }) : null
            ]
          }),
          card.tagline ? jsx('p', { className: 'max-w-3xl text-sm text-(--ui-text-tertiary)', children: card.tagline }) : null,
          ...asList(card.sections).map((part, index) =>
            jsx(
              Section,
              {
                title: part.title,
                help: part.help,
                children: asList(part.rows).map((row, rowIndex) =>
                  jsxs(
                    Row,
                    {
                      children: [
                        jsx(Badge, { variant: row.state === 'ok' || row.state === 'on' ? 'success' : row.state === 'warn' ? 'warn' : 'muted', children: row.icon || '·' }),
                        jsx(Grow, { children: row.text }),
                        row.sub ? jsx(Dim, { children: row.sub }) : null
                      ]
                    },
                    rowIndex
                  )
                )
              },
              index
            )
          ),
          jsx(Section, {
            title: 'Settings',
            children: Object.keys(section).length ? jsx(ShieldSettings, { shieldId: 'trader', section }) : jsx(Note, { children: 'Loading…' })
          }),
          jsx(Section, {
            title: 'Recent wallet events',
            help: 'Kept on this machine only.',
            children: eventRows.length
              ? eventRows.slice(0, 50).map((row, index) =>
                  jsxs(
                    Row,
                    {
                      children: [
                        jsx(Badge, { variant: row.decision === 'block' || row.blocked ? 'destructive' : 'warn', children: row.decision === 'block' || row.blocked ? 'blocked' : 'flagged' }),
                        jsx(Grow, { children: row.title || row.what || row.identifier || 'Wallet event' }),
                        jsx('span', { className: 'w-20 text-right text-[0.7rem] text-(--ui-text-quaternary)', children: when(row.ts) })
                      ]
                    },
                    index
                  )
                )
              : jsx(Note, { children: 'No wallet events yet.' })
          })
        ]
      })
    }
  })
}

// ---------------------------------------------------------------- Agents

function Agents() {
  const agents = useDash('agents', 'api/agents', POLL_MS)
  const targets = useDash('attach-targets', 'api/attach-targets')
  const [busy, setBusy] = useState(false)
  const protect = async (target, enabled) => {
    setBusy(true)
    const answer = await dash('api/agents/protection', { method: 'POST', body: { targets: [{ kind: target.kind, target: target.target, enabled }] } })
    setBusy(false)
    host.notify(answer && answer.ok
      ? { kind: 'success', message: `${enabled ? 'Protecting' : 'Stopped protecting'} ${target.target}. Restart that agent to apply.` }
      : { kind: 'error', message: `Could not change protection: ${(answer && answer.error) || 'unknown error'}` })
    refreshDash()
  }
  const rescan = async () => {
    await dash('api/agents/rescan', { method: 'POST', body: {} })
    refreshDash()
  }
  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsx(Section, {
        title: 'Protected agents',
        help: 'Hermes homes and profiles, and OpenClaw workspaces, that Blackbox watches. Changes apply after the agent restarts.',
        actions: jsx(Button, { size: 'sm', variant: 'outline', onClick: rescan, children: 'Rescan' }),
        children: jsx(DashState, {
          query: targets,
          children: data =>
            asList(asObject(data).targets).map((target, index) =>
              jsxs(
                Row,
                {
                  children: [
                    jsx(Badge, { variant: 'outline', children: target.kind }),
                    jsx(Grow, { children: target.target || target.disabled_reason || '–' }),
                    target.available === false
                      ? jsx(Dim, { children: 'not found on this machine' })
                      : jsx(Checkbox, { checked: target.protected, disabled: busy, label: target.protected ? 'Protected' : 'Not protected', onChange: next => protect(target, next) })
                  ]
                },
                index
              )
            )
        })
      }),
      jsx(Section, {
        title: 'Connected agents',
        children: jsx(DashState, {
          query: agents,
          children: data => {
            const rows = asList(asObject(data).agents)
            if (!rows.length) return jsx(Note, { children: 'No agent has been seen yet.' })
            return rows.map((row, index) =>
              jsxs(
                Row,
                {
                  children: [
                    jsx(Badge, { variant: row.is_active ? 'success' : 'muted', children: row.is_active ? 'active' : 'idle' }),
                    jsx(Grow, { children: `${row.framework || 'agent'} · ${row.workspace_label || row.workspace || ''}` }),
                    jsx(Dim, { children: `${num(row.findings)} findings · ${num(row.reports)} reports` })
                  ]
                },
                index
              )
            )
          }
        })
      })
    ]
  })
}

// ---------------------------------------------------------------- Community

function Community() {
  const stats = useDash('community-stats', 'api/community-stats')
  const trust = useDash('trust', 'api/trust')
  const reports = useDash('reports', 'api/reports')
  const [confirming, setConfirming] = useState(false)
  const setSharing = async on => {
    setConfirming(false)
    await saveSettings({ report: on }, on ? 'Sharing is on. You agreed to the reporter terms.' : 'Sharing is off.')
  }
  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsx(Section, {
        title: 'The community graph',
        help: 'Other Blackbox nodes report threats here; they only ever flag, never block. Your node reads them either way.',
        children: jsx(DashState, {
          query: stats,
          children: data => {
            const c = asObject(data)
            return jsxs('div', {
              className: 'flex flex-col gap-3',
              children: [
                jsxs('div', {
                  className: 'grid grid-cols-2 gap-4 sm:grid-cols-4',
                  children: [
                    jsx(Fact, { label: 'Joined', value: c.join_text || c.join_state || '–' }),
                    jsx(Fact, { label: 'Community threats', value: num(c.community_threats) }),
                    jsx(Fact, { label: 'Corroborated', value: num(c.corroborated_2plus) }),
                    jsx(Fact, { label: 'Contributing agents', value: num(c.contributing_agents) })
                  ]
                }),
                c.admission_text ? jsx(Dim, { children: c.admission_text }) : null,
                jsxs('div', {
                  className: 'flex flex-wrap items-center gap-2 text-sm text-(--ui-text-secondary)',
                  children: [
                    jsx(Label, { children: 'Sharing' }),
                    jsx(Badge, { variant: c.sharing_enabled ? 'success' : 'muted', children: c.sharing_enabled ? 'On' : 'Off' }),
                    c.sharing_enabled
                      ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => setSharing(false), children: 'Turn sharing off' })
                      : jsx(Button, { size: 'sm', variant: 'outline', onClick: () => setConfirming(true), children: 'Turn sharing on' })
                  ]
                }),
                confirming
                  ? jsxs('div', {
                      className: 'flex flex-col gap-2 text-sm text-(--ui-text-secondary)',
                      children: [
                        jsx('p', {
                          className: 'max-w-3xl',
                          children:
                            'Sharing sends privacy-safe, signed threat reports to the community graph: the threat’s name, category, severity and the day — never prompts, commands, file contents or secrets. Turning it on records your agreement to the reporter terms (blackbox report --consent shows them).'
                        }),
                        jsxs('div', {
                          className: 'flex gap-2',
                          children: [
                            jsx(Button, { size: 'sm', onClick: () => setSharing(true), children: 'I agree, turn sharing on' }),
                            jsx(Button, { size: 'sm', variant: 'outline', onClick: () => setConfirming(false), children: 'Cancel' })
                          ]
                        })
                      ]
                    })
                  : null
              ]
            })
          }
        })
      }),
      jsx(Section, {
        title: 'Who is trusted',
        children: jsx(DashState, {
          query: trust,
          children: data => {
            const t = asObject(data)
            const authorities = asList(t.authorities)
            return jsxs('div', {
              className: 'flex flex-col',
              children: [
                ...authorities.map((authority, index) =>
                  jsxs(
                    Row,
                    {
                      children: [
                        jsx(Badge, { variant: authority.trusted ? 'success' : 'muted', children: authority.trusted ? 'trusted' : authority.state || 'not trusted' }),
                        jsx(Grow, { children: `${authority.authority} authority` }),
                        jsx(Dim, { children: `${authority.threshold || '?'} of ${authority.keys || '?'} curators sign` })
                      ]
                    },
                    index
                  )
                ),
                jsx(Dim, { children: `${num(t.reporters_total)} trusted reporters · ${num(t.confirmed_total)} confirmed threats` })
              ]
            })
          }
        })
      }),
      jsx(Section, {
        title: 'Reports',
        children: jsx(DashState, {
          query: reports,
          children: data => {
            const r = asObject(data)
            const outbound = asList(r.outbound)
            const seen = asList(r.reports)
            return jsxs('div', {
              className: 'flex flex-col',
              children: [
                jsx(Label, { children: `Shared by this node (${outbound.length})` }),
                ...outbound.slice(0, 50).map((row, index) =>
                  jsxs(Row, { children: [jsx(Badge, { variant: 'outline', children: row.stage || row.outcome || 'sent' }), jsx(Grow, { children: row.identifier }), jsx(Dim, { children: row.day || '' })] }, `o${index}`)
                ),
                jsx('div', { className: 'pt-2' }),
                jsx(Label, { children: `Reported by the community (${seen.length})` }),
                ...seen.slice(0, 50).map((row, index) =>
                  jsxs(Row, { children: [jsx(Badge, { variant: severityVariant(row.severity), children: row.severity }), jsx(Grow, { children: row.identifier }), jsx(Dim, { children: `${row.reporters} reporter(s)` })] }, `s${index}`)
                )
              ]
            })
          }
        })
      })
    ]
  })
}

// ---------------------------------------------------------------- Settings

function SettingsForm({ initial }) {
  const [state, setState] = useState(() => ({
    mode: initial.mode === 'block' ? 'block' : 'audit',
    block_severity: initial.block_severity,
    report_min_severity: initial.report_min_severity,
    discover: !!initial.discover,
    osv_lookup: !!initial.osv_lookup,
    community_sandbox: !!initial.community_sandbox,
    categories: JSON.parse(JSON.stringify(asObject(initial.categories))),
    protected_paths: asList(initial.protected_paths)
  }))
  const [dirty, setDirty] = useState(false)
  const set = (key, value) => {
    setState(previous => ({ ...previous, [key]: value }))
    setDirty(true)
  }
  const setCategory = (key, field, value) => {
    setState(previous => ({ ...previous, categories: { ...previous.categories, [key]: { ...asObject(previous.categories[key]), [field]: value } } }))
    setDirty(true)
  }
  const labels = asObject(initial.category_labels)
  const save = async () => {
    if (state.mode === 'audit' && initial.mode === 'block') {
      // lowering protection from the form goes through the same confirmation as the switch
      host.notify({ kind: 'warning', message: 'Use the Overview switch to change to audit mode; it asks you to confirm first.' })
      return
    }
    const ok = await saveSettings(
      {
        mode: state.mode,
        block_severity: state.block_severity,
        report_min_severity: state.report_min_severity,
        discover: state.discover,
        osv_lookup: state.osv_lookup,
        community_sandbox: state.community_sandbox,
        report: !!initial.report, // sharing is changed on the Community tab, with its consent step
        categories: state.categories,
        protected_paths: state.protected_paths.slice(0, 100)
      },
      'Settings saved.'
    )
    if (ok) setDirty(false)
  }
  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsx(Section, {
        title: 'Blocking',
        children: jsxs('div', {
          className: 'flex flex-wrap items-center gap-4 text-sm text-(--ui-text-secondary)',
          children: [
            jsx(Badge, { variant: state.mode === 'block' ? 'success' : 'warn', children: `${modeLabel(state.mode)} mode` }),
            state.mode === 'audit' ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => set('mode', 'block'), children: 'Turn on blocking' }) : null,
            jsx(Label, { children: 'Lowest severity blocked' }),
            jsx(SeverityPick, { value: state.block_severity, onChange: value => set('block_severity', value) }),
            jsx(Label, { children: 'Lowest severity flagged' }),
            jsx(SeverityPick, { value: state.report_min_severity, onChange: value => set('report_min_severity', value) })
          ]
        })
      }),
      jsx(Section, {
        title: 'What Blackbox checks',
        children: Object.keys(state.categories).map(key =>
          jsxs(
            Row,
            {
              children: [
                jsx(Checkbox, { checked: asObject(state.categories[key]).enabled, label: labels[key] || key, onChange: value => setCategory(key, 'enabled', value) }),
                jsx('div', { className: 'flex-1' }),
                jsx(Dim, { children: 'from' }),
                jsx(SeverityPick, { value: asObject(state.categories[key]).min_severity, onChange: value => setCategory(key, 'min_severity', value) })
              ]
            },
            key
          )
        )
      }),
      jsx(Section, {
        title: 'Protected paths',
        help: 'Files and folders an agent may not read or copy. In block mode a match is refused; these rules never leave this machine. One per line.',
        children: jsx('textarea', {
          className: 'min-h-28 rounded border border-(--ui-stroke-secondary) bg-transparent p-2 font-mono text-[0.75rem] text-(--ui-text-secondary)',
          value: state.protected_paths.join('\n'),
          onChange: event => set('protected_paths', event.target.value.split('\n').map(line => line.trim()).filter(Boolean))
        })
      }),
      jsx(Section, {
        title: 'More',
        children: jsxs('div', {
          className: 'flex flex-col gap-2',
          children: [
            jsx(Checkbox, { checked: state.osv_lookup, label: 'Look packages up on OSV.dev (sends the package name and version, never your code)', onChange: value => set('osv_lookup', value) }),
            jsx(Checkbox, { checked: state.discover, label: 'Built-in checks for threats not yet in the graph (flag only)', onChange: value => set('discover', value) }),
            jsx(Checkbox, { checked: state.community_sandbox, label: 'Sandbox mode: Playground tests go to a test lane, never the real community graph', onChange: value => set('community_sandbox', value) })
          ]
        })
      }),
      jsxs('div', {
        className: 'flex gap-2',
        children: [
          jsx(Button, { size: 'sm', disabled: !dirty, onClick: save, children: 'Save settings' }),
          dirty ? jsx(Dim, { children: 'Unsaved changes' }) : null
        ]
      })
    ]
  })
}

function Settings() {
  const query = useDash('settings', 'api/settings')
  return jsx(DashState, {
    query,
    // keyed by the saved mode so a change made elsewhere (the switch, the dashboard) reloads the form
    children: data => jsx(SettingsForm, { initial: asObject(data) }, `${asObject(data).mode}-${asObject(data).block_severity}`)
  })
}

// ---------------------------------------------------------------- the page

function BlackboxPage({ ctx }) {
  const [tab, setTab] = useState('overview')
  const status = useStatus()
  const s = status.data

  if (s && !s.available) {
    return jsxs('div', {
      className: 'flex h-full flex-col gap-2 p-6 text-sm text-(--ui-text-secondary)',
      children: [
        jsx('div', { className: 'font-medium', children: 'Blackbox is not running in this Hermes' }),
        jsx('div', { className: 'text-(--ui-text-tertiary)', children: 'Enable the blackbox plugin (hermes plugins enable blackbox) and run hermes blackbox setup.' })
      ]
    })
  }

  const panels = {
    overview: () => (s ? jsx(Overview, { status: s, setTab }) : jsx(Note, { children: 'Loading…' })),
    threats: () => jsx(Threats, {}),
    activity: () => jsx(Activity, {}),
    graph: () => jsx(ThreatGraph, {}),
    trader: () => jsx(TraderShield, { ctx, dashboardUrl: s && s.dashboardUrl }),
    agents: () => jsx(Agents, {}),
    community: () => jsx(Community, {}),
    settings: () => jsx(Settings, {})
  }

  return jsxs('div', {
    className: 'flex h-full flex-col gap-4 overflow-auto p-6',
    children: [
      jsxs('div', {
        className: 'flex items-center gap-2',
        children: [
          jsx(Codicon, { name: 'shield', size: '20px' }),
          jsx('h1', { className: 'text-lg font-medium text-(--ui-text-secondary)', children: 'Agent Blackbox' }),
          s ? jsx(Badge, { variant: s.mode === 'block' ? 'success' : 'warn', children: `${modeLabel(s.mode)} mode` }) : null,
          jsx('div', { className: 'flex-1' }),
          s && s.dashboardUrl
            ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => openDashboard(ctx, s.dashboardUrl), children: 'Open in browser' })
            : null
        ]
      }),
      jsx('div', {
        className: 'flex flex-wrap gap-1 border-b border-(--ui-stroke-secondary) pb-2',
        role: 'tablist',
        children: TABS.map(([id, label]) =>
          jsx(
            Button,
            { size: 'sm', role: 'tab', 'aria-selected': tab === id, variant: tab === id ? 'secondary' : 'ghost', onClick: () => setTab(id), children: label },
            id
          )
        )
      }),
      panels[tab] ? panels[tab]() : null
    ]
  })
}

// ---------------------------------------------------------------- live alerts

function announce(ctx, finding) {
  if (!finding || typeof finding !== 'object') return
  const what = `${finding.title}${finding.tool ? ` (${finding.tool})` : ''}`
  const blocked = finding.outcome === 'blocked'
  host.notify({
    kind: blocked ? 'error' : 'warning',
    title: blocked ? 'Blackbox blocked an action' : 'Blackbox flagged an action',
    message: what,
    detail: [
      `${finding.severity} severity`,
      finding.more > 0 ? `${finding.more} more rule${finding.more === 1 ? '' : 's'} matched` : '',
      finding.sandbox ? 'Playground test' : ''
    ].filter(Boolean).join(' · ')
  })
  ctx.os.notify({
    title: blocked ? 'Blackbox blocked an action' : 'Blackbox flagged an action',
    body: what,
    activate: PAGE
  })
}

export default {
  id: 'blackbox',
  name: 'Agent Blackbox',
  register(ctx) {
    rest = ctx.rest
    ctx.onDispose(() => {
      rest = null
    })
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: PAGE }, render: () => jsx(BlackboxPage, { ctx }) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: PAGE, label: 'Blackbox', codicon: 'shield' } },
      { id: 'status', area: STATUSBAR_AREAS.right, order: 110, render: () => jsx(StatusChip, {}) }
    ])
    // Someone who switches Blackbox on in Desktop should not take audit mode for protection: once,
    // say plainly that it is recording, not blocking, with a one-click way to turn blocking on.
    ctx.setTimeout(() => {
      if (ctx.storage.get(AUDIT_NOTICE_KEY, false)) return
      fetchStatus().then(status => {
        if (!status || !status.available || status.mode !== 'audit') return
        ctx.storage.set(AUDIT_NOTICE_KEY, true)
        host.notify({
          kind: 'warning',
          persistent: true,
          title: 'Blackbox is recording, not blocking',
          message: 'It is in Audit mode: it flags threats but lets them run.',
          action: { label: 'Turn on blocking', onClick: () => setMode('block') },
          secondaryAction: { label: 'Open Blackbox', onClick: () => host.navigate(PAGE) }
        })
      }, () => {})
    }, 3000)
    ctx.onEvent('plugin.blackbox.finding', event => {
      queryClient.invalidateQueries({ queryKey: STATUS_KEY })
      queryClient.invalidateQueries({ queryKey: FINDINGS_KEY })
      refreshDash()
      announce(ctx, event && event.payload)
    })
  }
}
