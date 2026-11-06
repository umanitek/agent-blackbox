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

// The bubble map, the dashboard's graph view drawn natively: the tier at the centre, one bubble per
// threat type, one per threat (at most LEAVES_PER_TYPE each). A small force layout on a canvas —
// Desktop plugins load no libraries, so the dashboard's vendored force-graph cannot come along.
const LEAVES_PER_TYPE = 40
const SIMULATION_TICKS = 320

function buildBubbleGraph(centerLabel, threats, totals) {
  const nodes = [{ id: '__center__', kind: 'center', label: centerLabel, r: 22 }]
  const links = []
  const byType = new Map()
  for (const threat of threats) {
    const type = threat.category || 'other'
    if (!byType.has(type)) byType.set(type, [])
    const leaves = byType.get(type)
    if (leaves.length < LEAVES_PER_TYPE && !leaves.some(leaf => leaf.identifier === threat.identifier)) leaves.push(threat)
  }
  for (const [type, leaves] of byType) {
    const typeId = `type:${type}`
    const total = typeof totals[type] === 'number' ? totals[type] : leaves.length
    nodes.push({ id: typeId, kind: 'type', label: `${type} · ${total.toLocaleString()}`, r: 13 })
    links.push([0, nodes.length - 1, 120])
    const typeIndex = nodes.length - 1
    for (const leaf of leaves) {
      nodes.push({ id: leaf.identifier, kind: 'leaf', label: leaf.name || leaf.title || leaf.identifier, severity: leaf.severity, threat: leaf, r: 5 + Math.min(4, leaf.count || 0) })
      links.push([typeIndex, nodes.length - 1, 46])
    }
  }
  return { nodes, links }
}

function themeColor(element, name, fallback) {
  const value = getComputedStyle(element).getPropertyValue(name).trim()
  return value || fallback
}

function BubbleMap({ graph, onPick }) {
  const canvasRef = useRef(null)
  const [hover, setHover] = useState(null)
  const state = useRef({ nodes: [], hover: null })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined
    const nodes = graph.nodes.map((node, index) => ({
      ...node,
      x: Math.cos(index * 2.4) * (node.kind === 'leaf' ? 160 : 70),
      y: Math.sin(index * 2.4) * (node.kind === 'leaf' ? 160 : 70),
      vx: 0,
      vy: 0
    }))
    nodes[0].x = 0
    nodes[0].y = 0
    state.current.nodes = nodes
    let frame = 0
    let ticks = 0
    const colors = {}
    const readColors = () => {
      colors.center = themeColor(canvas, '--ui-accent', 'CanvasText')
      colors.type = themeColor(canvas, '--ui-text-secondary', 'CanvasText')
      colors.critical = themeColor(canvas, '--ui-red', themeColor(canvas, '--color-destructive', 'CanvasText'))
      colors.high = themeColor(canvas, '--color-destructive', colors.critical)
      colors.medium = themeColor(canvas, '--ui-accent-secondary', colors.type)
      colors.low = themeColor(canvas, '--ui-text-tertiary', colors.type)
      colors.link = themeColor(canvas, '--ui-stroke-secondary', colors.low)
      colors.text = themeColor(canvas, '--ui-text-secondary', 'CanvasText')
    }
    readColors()
    const resize = () => {
      const box = canvas.getBoundingClientRect()
      const scale = window.devicePixelRatio || 1
      canvas.width = Math.max(1, Math.floor(box.width * scale))
      canvas.height = Math.max(1, Math.floor(box.height * scale))
      ticks = Math.min(ticks, SIMULATION_TICKS - 60)   // settle again into the new space
    }
    const observer = new ResizeObserver(resize)
    observer.observe(canvas)
    resize()

    const step = () => {
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i]
          const b = nodes[j]
          let dx = b.x - a.x
          let dy = b.y - a.y
          const distance = Math.max(1, Math.hypot(dx, dy))
          const push = Math.min(4, 900 / (distance * distance))
          dx /= distance
          dy /= distance
          a.vx -= dx * push
          a.vy -= dy * push
          b.vx += dx * push
          b.vy += dy * push
        }
      }
      for (const [from, to, length] of graph.links) {
        const a = nodes[from]
        const b = nodes[to]
        const dx = b.x - a.x
        const dy = b.y - a.y
        const distance = Math.max(1, Math.hypot(dx, dy))
        const pull = (distance - length) * 0.02
        a.vx += (dx / distance) * pull
        a.vy += (dy / distance) * pull
        b.vx -= (dx / distance) * pull
        b.vy -= (dy / distance) * pull
      }
      for (const node of nodes) {
        if (node.kind === 'center') {
          node.x = 0
          node.y = 0
          continue
        }
        node.vx *= 0.82
        node.vy *= 0.82
        node.x += node.vx
        node.y += node.vy
      }
    }

    const draw = () => {
      const context = canvas.getContext('2d')
      const scale = window.devicePixelRatio || 1
      const width = canvas.width / scale
      const height = canvas.height / scale
      context.setTransform(scale, 0, 0, scale, width / 2, height / 2)
      context.clearRect(-width / 2, -height / 2, width, height)
      context.lineWidth = 1
      context.strokeStyle = colors.link
      context.globalAlpha = 0.6
      for (const [from, to] of graph.links) {
        context.beginPath()
        context.moveTo(nodes[from].x, nodes[from].y)
        context.lineTo(nodes[to].x, nodes[to].y)
        context.stroke()
      }
      for (const node of nodes) {
        const color = node.kind === 'center' ? colors.center : node.kind === 'type' ? colors.type : colors[node.severity] || colors.low
        context.globalAlpha = node.kind === 'leaf' ? 0.85 : 1
        context.fillStyle = color
        context.beginPath()
        context.arc(node.x, node.y, node.r + (state.current.hover === node ? 2 : 0), 0, Math.PI * 2)
        context.fill()
      }
      context.globalAlpha = 1
      context.fillStyle = colors.text
      context.font = '11px system-ui, sans-serif'
      context.textAlign = 'center'
      for (const node of nodes) {
        if (node.kind !== 'leaf' || state.current.hover === node) context.fillText(node.label, node.x, node.y + node.r + 13)
      }
    }

    // Animate while the layout settles, then stop: hover and resize ask for one more frame.
    const loop = () => {
      frame = 0
      if (ticks < SIMULATION_TICKS) {
        step()
        ticks++
      }
      draw()
      if (ticks < SIMULATION_TICKS) frame = requestAnimationFrame(loop)
    }
    const redraw = () => {
      if (!frame) frame = requestAnimationFrame(loop)
    }
    state.current.redraw = redraw
    observer.disconnect()
    const watcher = new ResizeObserver(() => {
      resize()
      redraw()
    })
    watcher.observe(canvas)
    redraw()
    return () => {
      if (frame) cancelAnimationFrame(frame)
      watcher.disconnect()
      state.current.redraw = null
    }
  }, [graph])

  const nodeAt = event => {
    const canvas = canvasRef.current
    const box = canvas.getBoundingClientRect()
    const x = event.clientX - box.left - box.width / 2
    const y = event.clientY - box.top - box.height / 2
    return state.current.nodes.find(node => Math.hypot(node.x - x, node.y - y) <= node.r + 3) || null
  }

  return jsxs('div', {
    className: 'relative',
    children: [
      jsx('canvas', {
        ref: canvasRef,
        className: 'h-[440px] w-full cursor-default rounded border border-(--ui-stroke-secondary)',
        onMouseMove: event => {
          const node = nodeAt(event)
          if (state.current.hover !== node) {
            state.current.hover = node
            setHover(node && node.kind === 'leaf' ? node : null)
            if (state.current.redraw) state.current.redraw()
          }
          event.currentTarget.style.cursor = node && node.kind === 'leaf' ? 'pointer' : 'default'
        },
        onMouseLeave: () => {
          state.current.hover = null
          setHover(null)
          if (state.current.redraw) state.current.redraw()
        },
        onClick: event => {
          const node = nodeAt(event)
          if (node && node.kind === 'leaf') onPick(node.threat)
        }
      }),
      hover
        ? jsx('div', {
            className: 'pointer-events-none absolute left-2 top-2 max-w-sm rounded border border-(--ui-stroke-secondary) bg-(--ui-bg-quaternary) px-2 py-1 text-[0.75rem] text-(--ui-text-secondary)',
            children: `${hover.severity || ''} · ${hover.label}${hover.threat && hover.threat.count > 1 ? ` · seen ${hover.threat.count}×` : ''}`
          })
        : null
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
      const pages = await Promise.all(types.map(type => dash(`api/graph?tier=${tier}&limit=${LEAVES_PER_TYPE}&category=${encodeURIComponent(type)}`)))
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
    return threats.length ? buildBubbleGraph(tierLabel, threats, totals) : null
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
