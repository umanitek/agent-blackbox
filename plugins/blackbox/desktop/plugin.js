// Agent Blackbox inside Hermes Desktop: a shield in the status bar, a Blackbox section in the
// sidebar with everything the Blackbox dashboard does (Overview, Threat graph, Settings, in the
// dashboard's own design), and an alert the moment Blackbox flags or
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
const POLL_MS = 4000 // the dashboard's own refresh; the live event refreshes at once
const SLOW_POLL_MS = 30000
const STATUS_KEY = ['blackbox', 'status']
const FINDINGS_KEY = ['blackbox', 'findings']
const AUDIT_NOTICE_KEY = 'auditNoticeShown' // ctx.storage: the one-time "recording, not blocking" notice
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
  return useQuery({ queryKey: ['blackbox', 'dash', key, path], queryFn: () => dash(path), refetchInterval: interval || POLL_MS })
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


// ---------------------------------------------------------------- Threat graph map

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

function seedLayout(nodes, links, previous) {
  // Bubbles the last graph also had (the centre, the hubs) start where they were, so switching tier
  // reshapes the map instead of redrawing it from nothing; the rest start next to their hub.
  const placed = new Set()
  nodes.forEach((node, index) => {
    const before = previous && previous.get(node.id)
    if (before) {
      node.x = before.x
      node.y = before.y
      placed.add(index)
    }
  })
  if (!placed.has(0)) {
    nodes[0].x = 0
    nodes[0].y = 0
    placed.add(0)
  }
  const queue = Array.from(placed)
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

function BubbleMap({ graph, loading, onPick }) {
  const wrapRef = useRef(null)
  const canvasRef = useRef(null)
  const [hover, setHover] = useState(null)
  const live = useRef({ nodes: [], links: [], view: { k: 1, x: 0, y: 0 }, hover: null, pointer: null, alpha: 1, wake: null, fitted: false })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined
    const state = live.current
    const previous = new Map(state.nodes.map(node => [node.id, node]))
    const nodes = graph.nodes.map(node => ({ ...node }))
    seedLayout(nodes, graph.links, previous)
    const carried = previous.size > 0
    state.nodes = nodes
    state.links = graph.links
    state.alpha = carried ? 0.6 : 1
    state.fitted = false
    state.target = null
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
          state.target = fitView(state.nodes, box.width, box.height)   // glide there, never jump
          state.fitted = true
        }
      }
      if (state.target) {
        const view = state.view
        const target = state.target
        const ease = 0.18
        state.view = { k: view.k + (target.k - view.k) * ease, x: view.x + (target.x - view.x) * ease, y: view.y + (target.y - view.y) * ease }
        if (Math.abs(target.k - view.k) < 0.002 && Math.abs(target.x - view.x) < 0.5 && Math.abs(target.y - view.y) < 0.5) {
          state.view = target
          state.target = null
        }
      }
      drawGraph(canvas, state.nodes, state.links, state.view, state.hover, theme)
      if (state.alpha > 0.004 || state.pointer || state.target) frame = requestAnimationFrame(loop)
    }
    const wake = () => {
      if (!frame) frame = requestAnimationFrame(loop)
    }
    state.wake = wake
    let sized = false
    const resize = () => {
      const box = size()
      const scale = window.devicePixelRatio || 1
      canvas.width = Math.max(1, Math.floor(box.width * scale))
      canvas.height = Math.max(1, Math.floor(box.height * scale))
      // the first frame of a fresh map fits at once; a resize or a tier switch glides
      if (!sized && !carried) state.view = fitView(state.nodes, box.width, box.height)
      else state.target = fitView(state.nodes, box.width, box.height)
      sized = true
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
    style: { position: 'relative', overflow: 'hidden' },
    children: [
      jsx('canvas', {
        ref: canvasRef,
        style: { display: 'block', width: '100%', height: 560, opacity: loading ? 0.55 : 1, transition: 'opacity .2s' },
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
            style: { position: 'absolute', left: 12, top: 12, maxWidth: 380, pointerEvents: 'none', padding: '8px 12px', borderRadius: 6,
              border: '1px solid var(--ui-stroke-secondary)', background: 'var(--background, #0b0b0d)', fontSize: 12.5 },
            children: [
              jsx('div', { style: { fontWeight: 600 }, children: hover.label }),
              jsx('div', { style: { color: 'var(--ui-text-tertiary)' }, children: `${hover.severity || 'unknown'} · ${GRAPH_CATEGORIES[hover.type] ? GRAPH_CATEGORIES[hover.type].name : 'Other'}${hover.threat.count > 1 ? ` · seen ${hover.threat.count}×` : ''}` })
            ]
          })
        : null,
      jsx('div', { style: { position: 'absolute', left: 14, bottom: 10, pointerEvents: 'none', fontSize: 11, color: 'var(--ui-text-quaternary)' }, children: 'Scroll to zoom · drag a bubble or the background · click a threat to open it' }),
      jsx('button', { type: 'button', className: 'bbx-iconbtn', title: 'Fullscreen', style: { position: 'absolute', right: 12, bottom: 12, background: 'var(--background, #0b0b0d)' }, onClick: toggleFullscreen, children: jsx(Codicon, { name: 'screen-full' }) })
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

// ---------------------------------------------------------------- the look
//
// The page carries its own small stylesheet (class prefix bbx-) in the Blackbox dashboard's design —
// uppercase monospace labels, large figures, outlined severity pills, quiet tables — on Desktop's
// theme variables, so it reads as Blackbox and still follows the app's light and dark themes. A disk
// plugin cannot rely on Tailwind classes the app itself never uses, so nothing here depends on them.
const SIGNAL = '#FF4F00' // the dashboard's signal orange (block mode, accents)
const PAGE_CSS = `
.bbx { --bbx-text: var(--ui-text-secondary); --bbx-muted: var(--ui-text-tertiary); --bbx-faint: var(--ui-text-quaternary);
  --bbx-line: var(--ui-stroke-secondary); --bbx-panel: color-mix(in srgb, var(--ui-text-secondary) 3%, transparent);
  --bbx-hover: color-mix(in srgb, var(--ui-text-secondary) 6%, transparent); --bbx-signal: ${SIGNAL};
  --bbx-mono: ui-monospace, SFMono-Regular, Menlo, monospace;
  color: var(--bbx-text); font-size: 14px; line-height: 1.5; height: 100%; overflow: auto; }
.bbx-wrap { max-width: 1240px; margin: 0 auto; padding: 28px 32px 64px; display: flex; flex-direction: column; gap: 40px; }
.bbx-top { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.bbx-brand { font-size: 26px; font-weight: 800; letter-spacing: -0.02em; display: flex; align-items: center; gap: 10px; }
.bbx-brand-dot { width: 16px; height: 16px; border-radius: 50%; background: var(--bbx-signal); display: inline-block; }
.bbx-spacer { flex: 1; }
.bbx-tabs { display: inline-flex; padding: 3px; border: 1px solid var(--bbx-line); border-radius: 6px; gap: 2px; }
.bbx-tab { font-family: var(--bbx-mono); font-size: 11.5px; letter-spacing: 0.08em; text-transform: uppercase; padding: 7px 14px;
  border-radius: 4px; border: 0; background: transparent; color: var(--bbx-muted); cursor: pointer; display: inline-flex; gap: 8px; align-items: center; }
.bbx-tab:hover { color: var(--bbx-text); background: var(--bbx-hover); }
.bbx-tab[aria-selected="true"] { background: var(--bbx-text); color: var(--background, #0b0b0d); }
.bbx-tab-count { font-size: 10.5px; padding: 1px 6px; border-radius: 3px; background: var(--bbx-hover); }
.bbx-tab[aria-selected="true"] .bbx-tab-count { background: color-mix(in srgb, var(--background, #0b0b0d) 20%, transparent); }
.bbx-modepill { font-family: var(--bbx-mono); font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; padding: 8px 14px;
  border-radius: 4px; border: 1px solid var(--bbx-line); color: var(--bbx-muted); background: transparent; cursor: pointer; }
.bbx-modepill.block { color: var(--bbx-signal); border-color: color-mix(in srgb, ${SIGNAL} 55%, transparent); background: color-mix(in srgb, ${SIGNAL} 10%, transparent); }
.bbx-iconbtn { width: 38px; height: 38px; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px;
  border: 1px solid var(--bbx-line); background: transparent; color: var(--bbx-text); cursor: pointer; }
.bbx-iconbtn:hover { background: var(--bbx-hover); }
.bbx-h2 { font-size: 22px; font-weight: 700; letter-spacing: -0.01em; margin: 0; }
.bbx-sub { color: var(--bbx-muted); margin: 4px 0 0; max-width: 72ch; }
.bbx-section { display: flex; flex-direction: column; gap: 16px; }
.bbx-head { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; }
.bbx-panel { border: 1px solid var(--bbx-line); border-radius: 6px; background: var(--bbx-panel); }
.bbx-label { font-family: var(--bbx-mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--bbx-muted); }
.bbx-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
@media (min-width: 1000px) { .bbx-stats { grid-template-columns: repeat(5, minmax(0, 1fr)); } }
.bbx-stat { padding: 16px 18px; display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.bbx-stat.warm { border-left: 3px solid color-mix(in srgb, ${SIGNAL} 60%, transparent); }
.bbx-stat-value { font-family: var(--bbx-mono); font-size: clamp(17px, 1.7vw, 24px); font-weight: 500; line-height: 1.15; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bbx-stat-note { font-family: var(--bbx-mono); font-size: 11.5px; color: var(--bbx-muted); line-height: 1.45; }
.bbx-stat .bbx-label { font-size: 10px; letter-spacing: 0.12em; }
.bbx-ok { color: #3FA568; font-family: var(--bbx-mono); font-size: 12.5px; font-weight: 600; }
.bbx-seg { display: inline-flex; padding: 3px; border: 1px solid var(--bbx-line); border-radius: 6px; gap: 2px; }
.bbx-seg button { font-family: var(--bbx-mono); font-size: 11.5px; padding: 6px 12px; border-radius: 4px; border: 0; background: transparent; color: var(--bbx-muted); cursor: pointer; }
.bbx-seg button[aria-pressed="true"] { background: var(--bbx-text); color: var(--background, #0b0b0d); }
.bbx-btn { font-size: 13px; font-weight: 600; padding: 8px 14px; border-radius: 6px; border: 1px solid var(--bbx-line); background: transparent; color: var(--bbx-text); cursor: pointer; }
.bbx-btn:hover { background: var(--bbx-hover); }
.bbx-btn.primary { background: var(--bbx-text); color: var(--background, #0b0b0d); border-color: var(--bbx-text); }
.bbx-btn.danger { color: #E5484D; border-color: color-mix(in srgb, #E5484D 45%, transparent); }
.bbx-btn:disabled { opacity: 0.45; cursor: default; }
.bbx-table { width: 100%; border-collapse: collapse; }
.bbx-table th { text-align: left; font-family: var(--bbx-mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--bbx-muted);
  font-weight: 500; padding: 14px 20px; border-bottom: 1px solid var(--bbx-line); }
.bbx-table td { padding: 14px 20px; border-bottom: 1px solid var(--bbx-line); vertical-align: top; }
.bbx-table tr:last-child td { border-bottom: 0; }
.bbx-table tbody tr:hover td { background: var(--bbx-hover); }
.bbx-mono { font-family: var(--bbx-mono); }
.bbx-small { font-size: 12px; color: var(--bbx-muted); }
.bbx-pill { display: inline-block; font-family: var(--bbx-mono); font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 3px; border: 1px solid; white-space: nowrap; }
.bbx-pill.critical { color: #E5484D; border-color: color-mix(in srgb, #E5484D 50%, transparent); background: color-mix(in srgb, #E5484D 10%, transparent); }
.bbx-pill.high { color: #F0657A; border-color: color-mix(in srgb, #F0657A 50%, transparent); background: color-mix(in srgb, #F0657A 9%, transparent); }
.bbx-pill.medium { color: #E5A00D; border-color: color-mix(in srgb, #E5A00D 50%, transparent); background: color-mix(in srgb, #E5A00D 9%, transparent); }
.bbx-pill.low, .bbx-pill.info, .bbx-pill.neutral { color: var(--bbx-muted); border-color: var(--bbx-line); background: var(--bbx-hover); }
.bbx-pill.ok { color: #3FA568; border-color: color-mix(in srgb, #3FA568 50%, transparent); background: color-mix(in srgb, #3FA568 9%, transparent); }
.bbx-pill.blocked { color: ${SIGNAL}; border-color: color-mix(in srgb, ${SIGNAL} 50%, transparent); background: color-mix(in srgb, ${SIGNAL} 9%, transparent); }
.bbx-type { display: inline-flex; align-items: center; gap: 8px; font-family: var(--bbx-mono); font-size: 13px; white-space: nowrap; }
.bbx-pager { display: flex; align-items: center; gap: 10px; padding: 12px 20px; border-top: 1px solid var(--bbx-line); }
.bbx-empty { padding: 28px 20px; color: var(--bbx-muted); }
.bbx-agents { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; padding: 22px; }
.bbx-agent { display: flex; gap: 14px; align-items: center; padding: 16px; border-radius: 6px; border: 1px solid color-mix(in srgb, ${SIGNAL} 45%, transparent);
  background: color-mix(in srgb, ${SIGNAL} 5%, transparent); }
.bbx-agent.off { border-color: var(--bbx-line); background: transparent; }
.bbx-avatar { width: 46px; height: 46px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 18px;
  background: var(--bbx-text); color: var(--background, #0b0b0d); flex: none; }
.bbx-attach { display: flex; gap: 14px; align-items: center; padding: 16px; border-radius: 6px; border: 1px dashed var(--bbx-line); background: transparent;
  color: var(--bbx-text); cursor: pointer; text-align: left; font-size: 15px; }
.bbx-attach:hover { background: var(--bbx-hover); }
.bbx-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.bbx-col { padding: 22px 24px; display: flex; flex-direction: column; gap: 16px; border-right: 1px solid var(--bbx-line); }
.bbx-col:last-child { border-right: 0; }
.bbx-check { display: flex; gap: 12px; align-items: flex-start; }
.bbx-mark { width: 22px; height: 22px; border-radius: 50%; border: 1.6px solid; display: inline-flex; align-items: center; justify-content: center; flex: none;
  font-size: 12px; font-weight: 700; margin-top: 1px; }
.bbx-mark.ok { color: #3FA568; } .bbx-mark.warn { color: #E5A00D; } .bbx-mark.none { color: var(--bbx-faint); } .bbx-mark.bad { color: #E5484D; }
.bbx-legend { display: flex; gap: 22px; flex-wrap: wrap; padding: 14px 24px; border-top: 1px solid var(--bbx-line); color: var(--bbx-muted); font-size: 13px; }
.bbx-legend span { display: inline-flex; gap: 8px; align-items: center; }
.bbx-sync { display: grid; grid-template-columns: 200px 1fr; gap: 28px; padding: 26px 28px; align-items: center; }
.bbx-bar { height: 6px; border-radius: 3px; background: var(--bbx-hover); overflow: hidden; }
.bbx-bar > i { display: block; height: 100%; background: #3F8F5F; border-radius: 3px; }
.bbx-barrow { display: grid; grid-template-columns: 170px 1fr auto; gap: 16px; align-items: center; }
.bbx-facts { display: flex; gap: 40px; flex-wrap: wrap; }
.bbx-fact-value { font-family: var(--bbx-mono); font-size: 20px; }
.bbx-input { font: inherit; padding: 9px 12px; border-radius: 6px; border: 1px solid var(--bbx-line); background: transparent; color: var(--bbx-text); min-width: 0; }
.bbx-select { font: inherit; font-size: 13px; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--bbx-line); background: transparent; color: var(--bbx-text); }
.bbx-textarea { font-family: var(--bbx-mono); font-size: 12.5px; padding: 10px 12px; border-radius: 6px; border: 1px solid var(--bbx-line); background: transparent; color: var(--bbx-text); min-height: 110px; width: 100%; box-sizing: border-box; }
.bbx-setrow { display: flex; align-items: center; gap: 16px; padding: 14px 22px; border-bottom: 1px solid var(--bbx-line); flex-wrap: wrap; }
.bbx-setrow:last-child { border-bottom: 0; }
.bbx-setrow-text { flex: 1; min-width: 220px; }
.bbx-setrow-title { font-weight: 600; }
.bbx-switch { position: relative; width: 38px; height: 22px; border-radius: 11px; border: 0; background: var(--bbx-line); cursor: pointer; flex: none; }
.bbx-switch::after { content: ""; position: absolute; top: 3px; left: 3px; width: 16px; height: 16px; border-radius: 50%; background: var(--background, #0b0b0d); transition: left .15s; }
.bbx-switch[aria-checked="true"] { background: #3F8F5F; }
.bbx-switch[aria-checked="true"]::after { left: 19px; }
.bbx-savebar { position: sticky; bottom: 0; display: flex; gap: 12px; align-items: center; padding: 14px 22px; border-top: 1px solid var(--bbx-line);
  background: var(--background, #0b0b0d); }
.bbx-confirm { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; padding: 14px 22px; border-top: 1px solid var(--bbx-line);
  background: color-mix(in srgb, ${SIGNAL} 6%, transparent); }
.bbx-graphwrap { padding: 0; overflow: hidden; }
.bbx-searchbar { display: flex; gap: 10px; align-items: center; padding: 14px 20px; border-bottom: 1px solid var(--bbx-line); flex-wrap: wrap; }
.bbx-ready { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr); gap: 40px; align-items: start; }
@media (max-width: 960px) { .bbx-ready { grid-template-columns: 1fr; } }
.bbx-ready-main { display: flex; flex-direction: column; gap: 22px; padding-top: 12px; }
.bbx-kicker { font-family: var(--bbx-mono); font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase; color: var(--bbx-signal); }
.bbx-hero { font-size: 38px; line-height: 1.08; font-weight: 800; letter-spacing: -0.025em; margin: -8px 0 0; text-wrap: balance; }
.bbx-hero-sub { font-size: 15.5px; line-height: 1.6; color: var(--bbx-muted); margin: 0; max-width: 60ch; }
.bbx-shieldnote { display: flex; gap: 10px; align-items: flex-start; padding: 12px 14px; border-radius: 6px; font-size: 13px;
  color: #3FA568; border: 1px solid color-mix(in srgb, #3FA568 35%, transparent); background: color-mix(in srgb, #3FA568 7%, transparent); }
.bbx-alert { padding: 12px 14px; border-radius: 6px; font-family: var(--bbx-mono); font-size: 12.5px; color: #E5484D;
  border: 1px solid color-mix(in srgb, #E5484D 40%, transparent); background: color-mix(in srgb, #E5484D 7%, transparent); }
.bbx-ready-actions { display: flex; flex-direction: column; gap: 10px; align-items: flex-start; }
.bbx-cta { font-size: 15px; font-weight: 700; padding: 13px 26px; border-radius: 6px; border: 0; cursor: pointer; color: #fff;
  background: var(--bbx-signal); box-shadow: 0 8px 24px -10px ${SIGNAL}; transition: transform .12s, filter .12s; margin-bottom: 6px; }
.bbx-cta:hover { filter: brightness(1.08); transform: translateY(-1px); }
.bbx-cta:disabled { opacity: 0.6; cursor: default; transform: none; }
.bbx-cmd { display: inline-flex; align-items: center; gap: 10px; padding: 6px 6px 6px 14px; border-radius: 6px; border: 1px solid var(--bbx-line);
  background: var(--bbx-panel); font-family: var(--bbx-mono); font-size: 13px; max-width: 100%; }
.bbx-cmd code { font-family: inherit; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bbx-cmd-prompt { color: var(--bbx-faint); }
.bbx-cmd .bbx-btn { padding: 5px 10px; font-size: 12px; }
.bbx-disclose { display: flex; flex-direction: column; gap: 10px; padding-top: 6px; border-top: 1px solid var(--bbx-line); }
.bbx-disclose .bbx-label { padding-top: 16px; }
.bbx-disclose-row { display: grid; grid-template-columns: 18px 1fr; gap: 12px; font-size: 13px; color: var(--bbx-muted); line-height: 1.5; }
.bbx-disclose-row .codicon { margin-top: 2px; color: var(--bbx-text); }
.bbx-stepper { overflow: hidden; }
.bbx-preview { padding: 24px 26px; display: flex; flex-direction: column; gap: 16px; }
.bbx-progress { height: 3px; background: var(--bbx-hover); }
.bbx-progress > i { display: block; height: 100%; background: var(--bbx-signal); transition: width .6s ease; }
.bbx-stepper-head { display: flex; align-items: center; padding: 16px 22px 6px; }
.bbx-steps { list-style: none; margin: 0; padding: 6px 0 10px; }
.bbx-step { display: grid; grid-template-columns: 28px 1fr; gap: 14px; padding: 11px 22px; align-items: start; color: var(--bbx-faint); }
.bbx-step.done { color: var(--bbx-muted); }
.bbx-step.active { color: var(--bbx-text); background: color-mix(in srgb, ${SIGNAL} 6%, transparent); }
.bbx-step.failed { color: #E5484D; }
.bbx-step-label { font-size: 14.5px; font-weight: 600; padding-top: 3px; }
.bbx-step-detail { font-family: var(--bbx-mono); font-size: 12px; color: var(--bbx-muted); margin-top: 4px; }
.bbx-stepmark { width: 26px; height: 26px; border-radius: 50%; border: 1.5px solid var(--bbx-line); display: inline-flex; align-items: center;
  justify-content: center; font-family: var(--bbx-mono); font-size: 11.5px; }
.bbx-stepmark.done { border-color: #3FA568; background: #3FA568; color: #fff; }
.bbx-stepmark.active { border-color: var(--bbx-signal); color: var(--bbx-signal); }
.bbx-stepmark.failed { border-color: #E5484D; background: #E5484D; color: #fff; }
.bbx-spin { width: 12px; height: 12px; border-radius: 50%; border: 2px solid currentColor; border-right-color: transparent; display: inline-block;
  animation: bbx-spin .8s linear infinite; }
.bbx-spin.big { width: 54px; height: 54px; border-width: 3px; color: var(--bbx-signal); position: absolute; }
@keyframes bbx-spin { to { transform: rotate(360deg); } }
.bbx-logwrap { border-top: 1px solid var(--bbx-line); padding: 12px 22px 16px; display: flex; flex-direction: column; gap: 10px; }
.bbx-linkbtn { display: inline-flex; gap: 6px; align-items: center; border: 0; background: transparent; color: var(--bbx-muted); cursor: pointer; font-size: 12.5px; padding: 0; }
.bbx-linkbtn:hover { color: var(--bbx-text); }
.bbx-log { margin: 0; max-height: 240px; overflow: auto; font-family: var(--bbx-mono); font-size: 11.5px; line-height: 1.55; white-space: pre-wrap;
  color: var(--bbx-muted); background: var(--bbx-panel); border: 1px solid var(--bbx-line); border-radius: 6px; padding: 12px 14px; }
.bbx-syncbanner { display: flex; gap: 24px; align-items: center; padding: 22px 24px; flex-wrap: wrap;
  border-left: 3px solid var(--bbx-signal); background: color-mix(in srgb, ${SIGNAL} 4%, var(--bbx-panel)); }
.bbx-syncbanner-ring { position: relative; width: 54px; height: 54px; display: flex; align-items: center; justify-content: center; font-size: 13px; font-weight: 600; flex: none; }
.bbx-modal-backdrop { position: fixed; inset: 0; z-index: 60; background: color-mix(in srgb, #000 55%, transparent); display: flex;
  align-items: flex-start; justify-content: center; padding: 6vh 24px; overflow: auto; }
.bbx-modal { width: min(760px, 100%); background: var(--background, #0b0b0d); border: 1px solid var(--bbx-line); border-radius: 10px;
  box-shadow: 0 30px 80px -20px #000; display: flex; flex-direction: column; max-height: 88vh; }
.bbx-modal-head { display: flex; gap: 16px; align-items: flex-start; padding: 22px 24px 16px; border-bottom: 1px solid var(--bbx-line); }
.bbx-modal-title { font-size: 21px; font-weight: 750; margin: 0; letter-spacing: -0.01em; word-break: break-word; }
.bbx-modal-body { padding: 20px 24px 24px; overflow: auto; }
.bbx-kv { display: grid; grid-template-columns: minmax(120px, 170px) 1fr; gap: 10px 18px; margin: 0; }
.bbx-kv dt { font-family: var(--bbx-mono); font-size: 10.5px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--bbx-muted); padding-top: 3px; }
.bbx-kv dd { margin: 0; word-break: break-word; }
.bbx-row-open { cursor: pointer; }
.bbx-engage { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; padding: 22px 26px; border-color: color-mix(in srgb, ${SIGNAL} 45%, transparent);
  background: radial-gradient(120% 140% at 100% 50%, color-mix(in srgb, ${SIGNAL} 12%, transparent), transparent 60%), var(--bbx-panel); }
.bbx-engage .bbx-cta { margin: 0; }
.bbx-engage-title { font-size: 24px; font-weight: 800; letter-spacing: -0.01em; margin: 4px 0 2px; }
.bbx-shieldline { display: flex; gap: 14px; align-items: center; padding: 14px 18px; }
`

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const EVENT_LABELS = {
  session_start: 'Session started', session_end: 'Session ended', message_received: 'Message received',
  pre_api_request: 'API request', pre_tool_call: 'Tool call', post_tool_call: 'Tool result',
  file_access: 'File access', dependency_install: 'Package install', flagged: 'Threat flagged', blocked: 'Threat blocked'
}
const TYPE_LABELS = {
  dependency: 'Dependency', injection: 'Prompt injection', escalation: 'Escalation', fileaccess: 'File access',
  skill: 'Suspicious skill', secret: 'Secret exposure', ioc: 'Indicator', other: 'Other'
}
const PAGE_SIZE = 10
const cap = text => (text ? text.charAt(0).toUpperCase() + text.slice(1) : '')

function timeCell(seconds) {
  if (typeof seconds !== 'number' || !seconds) return jsx('span', { className: 'bbx-small', children: '–' })
  const date = new Date(seconds * 1000)
  const today = new Date()
  const sameDay = date.toDateString() === today.toDateString()
  return jsxs('div', {
    children: [
      jsx('div', { className: 'bbx-mono', children: date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' }) }),
      jsx('div', { className: 'bbx-small bbx-mono', children: sameDay ? 'Today' : date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) })
    ]
  })
}

function Pill({ tone, children }) {
  return jsx('span', { className: `bbx-pill ${tone || 'neutral'}`, children })
}

function TypeCell({ type }) {
  const key = TYPE_LABELS[type] ? type : 'other'
  return jsxs('span', {
    className: 'bbx-type',
    children: [
      jsx('svg', {
        width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke: (GRAPH_CATEGORIES[key] || GRAPH_CATEGORIES.other).color,
        strokeWidth: 1.9, strokeLinecap: 'round', strokeLinejoin: 'round',
        children: (GRAPH_ICONS[key] || GRAPH_ICONS.other).map((d, index) => jsx('path', { d }, index))
      }),
      TYPE_LABELS[key]
    ]
  })
}

function Switch({ checked, onChange, label, disabled }) {
  return jsx('button', {
    type: 'button', role: 'switch', 'aria-checked': checked ? 'true' : 'false', 'aria-label': label, disabled: !!disabled,
    className: 'bbx-switch', onClick: () => onChange(!checked)
  })
}

function Segmented({ value, options, onChange }) {
  return jsx('div', {
    className: 'bbx-seg',
    children: options.map(([id, label]) => jsx('button', { type: 'button', 'aria-pressed': value === id ? 'true' : 'false', onClick: () => onChange(id), children: label }, id))
  })
}

function Pager({ page, pages, total, onPage }) {
  if (pages <= 1) return null
  return jsxs('div', {
    className: 'bbx-pager',
    children: [
      jsx('span', { className: 'bbx-small bbx-mono', children: `${(page * PAGE_SIZE + 1).toLocaleString()}–${Math.min(total, (page + 1) * PAGE_SIZE).toLocaleString()} of ${total.toLocaleString()}` }),
      jsx('div', { className: 'bbx-spacer' }),
      jsx('button', { type: 'button', className: 'bbx-btn', disabled: page === 0, onClick: () => onPage(page - 1), children: 'Previous' }),
      jsx('span', { className: 'bbx-small bbx-mono', children: `${page + 1} / ${pages}` }),
      jsx('button', { type: 'button', className: 'bbx-btn', disabled: page >= pages - 1, onClick: () => onPage(page + 1), children: 'Next' })
    ]
  })
}

function Loading({ query, children, empty }) {
  const data = query.data
  if (query.isLoading) return jsx('div', { className: 'bbx-empty', children: 'Loading…' })
  if (data && data.dashboardDown)
    return jsx('div', { className: 'bbx-empty', children: 'The Blackbox dashboard service is not running, so this cannot load. It starts at login; to start it now, run blackbox dashboard in a terminal.' })
  if (data && data.error && !Array.isArray(data)) return jsx('div', { className: 'bbx-empty', children: `Could not load: ${data.error}` })
  const content = children(data)
  return content == null ? jsx('div', { className: 'bbx-empty', children: empty || 'Nothing here yet.' }) : content
}

function Heading({ title, sub, actions }) {
  return jsxs('div', {
    className: 'bbx-head',
    children: [
      jsxs('div', { children: [jsx('h2', { className: 'bbx-h2', children: title }), sub ? jsx('p', { className: 'bbx-sub', children: sub }) : null] }),
      jsx('div', { className: 'bbx-spacer' }),
      actions || null
    ]
  })
}

function openDashboard(ctx, url) {
  ctx.os.openExternal(url).then(opened => {
    if (!opened) host.notify({ kind: 'warning', message: `Open ${url} in your browser` })
  })
}

// ---------------------------------------------------------------- Overview

function ago(seconds) {
  if (typeof seconds !== 'number' || seconds <= 0) return '–'
  const elapsed = Math.max(0, Date.now() / 1000 - seconds)
  if (elapsed < 60) return `${Math.round(elapsed)}s ago`
  if (elapsed < 3600) return `${Math.round(elapsed / 60)}m ago`
  if (elapsed < 86400) return `${Math.round(elapsed / 3600)}h ago`
  return `${Math.round(elapsed / 86400)}d ago`
}

function StatCards({ status }) {
  const graph = useDash('graph-status', 'api/graph-status')
  const community = useDash('community-stats', 'api/community-stats')
  const findings = useDash('findings-all', 'api/findings?limit=500', POLL_MS)
  const settings = useDash('settings', 'api/settings')
  const g = asObject(graph.data)
  const c = asObject(community.data)
  const rows = asList(asObject(findings.data).findings)
  const critical = rows.filter(row => row.severity === 'critical').length
  const sharing = !!asObject(settings.data).report
  const minutes = g.sync_interval ? Math.round(g.sync_interval / 60) : null
  const card = (icon, label, value, note, extra, warm) =>
    jsxs('div', {
      className: `bbx-panel bbx-stat${warm ? ' warm' : ''}`,
      children: [
        jsxs('div', { className: 'bbx-label', style: { display: 'flex', gap: 8, alignItems: 'center' }, children: [jsx(Codicon, { name: icon }), label] }),
        jsx('div', { className: 'bbx-stat-value', children: value }),
        note ? jsx('div', { className: 'bbx-stat-note', children: note }) : null,
        extra || null
      ]
    })
  return jsxs('div', {
    className: 'bbx-stats',
    children: [
      card('warning', 'Open findings', num(asObject(findings.data).total ?? rows.length), `${critical} critical`),
      card('shield', 'Verified threats synced', num(g.curated), "from Umanitek's curated graph"),
      card('history', 'Last sync', ago(g.last_sync), minutes ? `auto every ${minutes >= 60 ? `${Math.round(minutes / 60)}h` : `${minutes}m`}` : ''),
      card('organization', 'Community graph', num(c.community_threats), [c.graph && c.graph.split('/').pop(), `${num(c.contributing_agents)} agents`, `${num(c.corroborated_2plus)} with 2+ reporters`].filter(Boolean).join(' · '),
        c.join_state ? jsx('div', { className: 'bbx-ok', children: c.join_text || c.join_state }) : null, true),
      card('broadcast', 'Threat sharing', sharing ? 'on' : 'off', sharing ? 'privacy-safe reports to the community' : 'opt in from settings', null, true)
    ]
  })
}

function ModeCard({ mode, blockSeverity }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const choose = async next => {
    setBusy(true)
    await setMode(next)
    setBusy(false)
    setConfirming(false)
  }
  return jsxs('div', {
    className: 'bbx-panel',
    children: [
      jsxs('div', {
        className: 'bbx-setrow',
        children: [
          jsxs('div', {
            className: 'bbx-setrow-text',
            children: [
              jsx('div', { className: 'bbx-setrow-title', children: mode === 'block' ? 'Block mode: Blackbox stops threats' : 'Audit mode: Blackbox records threats but does not stop them' }),
              jsx('div', {
                className: 'bbx-small',
                children: mode === 'block'
                  ? `Every tool call and model request is checked before it runs; verified threats at or above ${blockSeverity} severity, your protected paths and secrets sent off the machine are refused.`
                  : 'Every tool call and model request is checked and recorded. Nothing is stopped until you turn on blocking.'
              })
            ]
          }),
          jsxs('div', {
            className: 'bbx-seg',
            children: [
              jsx('button', { type: 'button', 'aria-pressed': mode === 'audit' ? 'true' : 'false', disabled: busy || mode === 'audit', onClick: () => (mode === 'audit' ? null : setConfirming(true)), children: 'Audit: record only' }),
              jsx('button', { type: 'button', 'aria-pressed': mode === 'block' ? 'true' : 'false', disabled: busy || mode === 'block', onClick: () => choose('block'), children: 'Block: stop threats' })
            ]
          })
        ]
      }),
      // switching to audit lowers protection, so it takes a second, explicit click
      confirming
        ? jsxs('div', {
            className: 'bbx-confirm',
            children: [
              jsx('span', { children: 'Switch to audit? Blackbox will keep recording threats but will stop blocking them.' }),
              jsx('div', { className: 'bbx-spacer' }),
              jsx('button', { type: 'button', className: 'bbx-btn danger', disabled: busy, onClick: () => choose('audit'), children: 'Switch to audit' }),
              jsx('button', { type: 'button', className: 'bbx-btn', disabled: busy, onClick: () => setConfirming(false), children: 'Keep blocking' })
            ]
          })
        : null
    ]
  })
}

function ConnectedAgents() {
  const agents = useDash('agents', 'api/agents', POLL_MS)
  const targets = useDash('attach-targets', 'api/attach-targets')
  const [choosing, setChoosing] = useState(false)
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
  const a = asObject(agents.data)
  const list = asList(a.agents).filter(agent => agent.is_local !== false)
  return jsxs('section', {
    className: 'bbx-section',
    children: [
      jsx(Heading, {
        title: 'Connected agents',
        actions: jsxs('div', {
          style: { display: 'flex', gap: 12, alignItems: 'center' },
          children: [
            jsx('span', { className: 'bbx-small', children: `${num(a.connected_count ?? list.length)} connected agent${a.connected_count === 1 ? '' : 's'}` }),
            jsx('button', { type: 'button', className: 'bbx-iconbtn', title: 'Rescan this machine for agents', onClick: rescan, children: jsx(Codicon, { name: 'refresh' }) })
          ]
        })
      }),
      jsxs('div', {
        className: 'bbx-panel',
        children: [
          jsxs('div', {
            className: 'bbx-agents',
            children: [
              ...list.map((agent, index) =>
                jsxs(
                  'div',
                  {
                    className: `bbx-agent${agent.is_active === false ? ' off' : ''}`,
                    children: [
                      jsx('div', { className: 'bbx-avatar', children: (agent.framework || 'A').charAt(0).toUpperCase() }),
                      jsxs('div', {
                        style: { minWidth: 0 },
                        children: [
                          jsx('div', { style: { fontWeight: 700, fontSize: 15 }, children: agent.blackbox_host ? 'Blackbox Hermes Agent' : `${cap(agent.framework || 'agent')} agent` }),
                          jsx('div', { className: 'bbx-small bbx-mono', style: { overflow: 'hidden', textOverflow: 'ellipsis' }, children: agent.workspace_label || agent.workspace || '' }),
                          jsx('div', { className: 'bbx-label', style: { color: agent.is_active === false ? undefined : SIGNAL, marginTop: 4 }, children: agent.is_active === false ? 'Idle' : 'Connected' })
                        ]
                      })
                    ]
                  },
                  index
                )
              ),
              jsxs('button', {
                type: 'button', className: 'bbx-attach', onClick: () => setChoosing(!choosing),
                children: [jsx('span', { className: 'bbx-iconbtn', style: { pointerEvents: 'none' }, children: jsx(Codicon, { name: 'add' }) }), choosing ? 'Close' : 'Attach agent']
              })
            ]
          }),
          choosing
            ? jsx(Loading, {
                query: targets,
                children: data =>
                  jsx('div', {
                    style: { borderTop: '1px solid var(--bbx-line)' },
                    children: asList(asObject(data).targets).map((target, index) =>
                      jsxs(
                        'div',
                        {
                          className: 'bbx-setrow',
                          children: [
                            jsxs('div', {
                              className: 'bbx-setrow-text',
                              children: [
                                jsx('div', { className: 'bbx-setrow-title', children: target.kind === 'hermes' ? 'Hermes' : target.kind === 'openclaw' ? 'OpenClaw' : target.kind }),
                                jsx('div', { className: 'bbx-small bbx-mono', children: target.target || target.disabled_reason || '' })
                              ]
                            }),
                            target.available === false
                              ? jsx('span', { className: 'bbx-small', children: 'Not found on this machine' })
                              : jsx(Switch, { checked: !!target.protected, disabled: busy, label: `Protect ${target.target}`, onChange: next => protect(target, next) })
                          ]
                        },
                        index
                      )
                    )
                  })
              })
            : null
        ]
      })
    ]
  })
}

// Turn a shield on or off: the dashboard's own switch (POST /api/settings, shields.<id>.enabled), so an
// earlier choice of wallets and addresses is kept.
async function setShield(card, enabled) {
  return saveSettings(
    { shields: { [card.shield_id]: { enabled } } },
    enabled ? `${card.name} is engaged. Restart your agent so it picks the change up.` : `${card.name} is off.`
  )
}

const shieldCards = data => asList(data).filter(item => item && item.shield_id)
const shieldOn = card => !!asObject(card.mode).enabled

// What a shield protects on this machine (its status columns) and its recent events.
function ShieldStatus({ card }) {
  const events = useDash(`shield-events-${card.shield_id}`, `api/shields/${card.shield_id}/events`, POLL_MS)
  const engaged = shieldOn(card)
  // The shield's row states (shields/trader/status.py): ok ✓ secured, watch ~ watched (flagged only),
  // none – not protected, warn ! needs attention — drawn as the dashboard draws them (static/shields.js).
  const markTone = state => ({ ok: 'ok', watch: 'warn', warn: 'bad', none: 'none' })[state] || 'none'
  const markGlyph = tone => ({ ok: '✓', warn: '~', none: '–', bad: '!' })[tone]
  const eventRows = asList(events.data)
  return jsxs('div', {
    children: [
      jsxs('div', {
        className: 'bbx-panel',
        children: [
          jsxs('div', {
            className: 'bbx-cols',
            children: [
              ...asList(card.sections).map((part, index) =>
                jsxs(
                  'div',
                  {
                    className: 'bbx-col',
                    children: [
                      jsx('div', { className: 'bbx-label', title: part.help || '', children: part.title }),
                      ...asList(part.rows).map((row, rowIndex) => {
                        const tone = markTone(row.state)
                        return jsxs(
                          'div',
                          {
                            className: 'bbx-check',
                            children: [
                              jsx('span', { className: `bbx-mark ${tone}`, children: markGlyph(tone) }),
                              jsxs('div', { children: [jsx('div', { style: { fontWeight: 600 }, children: row.text }), row.sub ? jsx('div', { className: 'bbx-small', children: row.sub }) : null] })
                            ]
                          },
                          rowIndex
                        )
                      })
                    ]
                  },
                  index
                )
              ),
              jsxs('div', {
                className: 'bbx-col',
                children: [
                  jsx('div', { className: 'bbx-label', children: 'Recent events' }),
                  eventRows.length
                    ? eventRows.slice(0, 6).map((row, index) =>
                        jsxs('div', { className: 'bbx-check', children: [jsx('span', { className: `bbx-mark ${row.decision === 'block' || row.blocked ? 'bad' : 'warn'}`, children: '!' }), jsxs('div', { children: [jsx('div', { style: { fontWeight: 600 }, children: row.title || row.what || 'Wallet event' }), jsx('div', { className: 'bbx-small', children: when(row.ts) })] })] }, index)
                      )
                    : jsx('div', { className: 'bbx-small', children: 'Nothing yet — no agent has reached for anything Trader Shield protects.' })
                ]
              })
            ]
          }),
          jsxs('div', {
            className: 'bbx-legend',
            children: [
              jsxs('span', { children: [jsx('span', { className: 'bbx-mark ok', children: '✓' }), 'secured — blocked'] }),
              jsxs('span', { children: [jsx('span', { className: 'bbx-mark warn', children: '~' }), 'watched — flagged only (audit mode)'] }),
              jsxs('span', { children: [jsx('span', { className: 'bbx-mark none', children: '–' }), 'not protected'] }),
              jsxs('span', { children: [jsx('span', { className: 'bbx-mark bad', children: '!' }), 'needs attention'] })
            ]
          })
        ]
      })
    ]
  })
}

// Overview's shield line: the dashboard's "Engage" banner while a shield is off, a one-line status once on.
function ShieldBanner({ setTab }) {
  const cards = useDash('shields', 'api/shields')
  const [busy, setBusy] = useState('')
  return jsx('div', {
    style: { display: 'flex', flexDirection: 'column', gap: 12 },
    children: shieldCards(cards.data).map(card => {
      if (shieldOn(card))
        return jsxs('div', {
          className: 'bbx-panel bbx-shieldline',
          children: [
            jsx(Codicon, { name: 'shield' }),
            jsxs('div', {
              style: { flex: 1, minWidth: 0 },
              children: [
                jsxs('div', { style: { fontWeight: 700 }, children: [card.name, jsx('span', { className: 'bbx-ok', style: { marginLeft: 10 }, children: card.blocking ? '● Blocking' : '● Watching' })] }),
                jsx('div', { className: 'bbx-small', children: card.tagline })
              ]
            }),
            jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => setTab('shields'), children: 'Open Shields' })
          ]
        }, card.shield_id)
      return jsxs('div', {
        className: 'bbx-panel bbx-engage',
        children: [
          jsxs('div', {
            style: { flex: 1, minWidth: 220 },
            children: [
              jsx('div', { className: 'bbx-kicker', children: card.beta ? 'New · Beta' : 'New' }),
              jsx('div', { className: 'bbx-engage-title', children: card.name }),
              jsx('div', { className: 'bbx-sub', children: card.tagline })
            ]
          }),
          jsxs('div', {
            style: { display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' },
            children: [
              jsx('button', {
                type: 'button',
                className: 'bbx-cta',
                disabled: busy === card.shield_id,
                onClick: async () => {
                  setBusy(card.shield_id)
                  await setShield(card, true)
                  setBusy('')
                },
                children: busy === card.shield_id ? 'Engaging…' : `Engage ${card.name}`
              }),
              jsx('button', { type: 'button', className: 'bbx-btn', style: { padding: '12px 18px' }, onClick: () => setTab('shields'), children: 'Learn more →' })
            ]
          })
        ]
      }, card.shield_id)
    })
  })
}

// The Shields tab: each shield with its switch, what it protects on this machine, its recent events
// and its settings. The one place a shield is set up; Overview only engages it.
function ShieldsTab() {
  const cards = useDash('shields', 'api/shields')
  const settings = useDash('settings', 'api/settings')
  const [confirming, setConfirming] = useState('')
  const sections = asObject(asObject(settings.data).shields)
  return jsx('div', {
    className: 'bbx-wrap',
    style: { padding: 0 },
    children: jsx(Loading, {
      query: cards,
      empty: 'No shields are available in this Blackbox.',
      children: data => {
        const list = shieldCards(data)
        if (!list.length) return null
        return jsxs('div', {
          style: { display: 'flex', flexDirection: 'column', gap: 40 },
          children: list.map(card => {
            const engaged = shieldOn(card)
            const section = asObject(sections[card.shield_id])
            return jsxs('section', {
              className: 'bbx-section',
              children: [
                jsx(Heading, {
                  title: jsxs('span', { style: { display: 'inline-flex', gap: 12, alignItems: 'center' }, children: [card.name, card.beta ? jsx(Pill, { tone: 'blocked', children: 'BETA' }) : null] }),
                  sub: card.tagline,
                  actions: jsxs('div', {
                    style: { display: 'flex', gap: 12, alignItems: 'center' },
                    children: [
                      jsx(Pill, { tone: engaged ? (card.blocking ? 'ok' : 'medium') : 'neutral', children: engaged ? (card.blocking ? '● Blocking' : '● Watching') : 'Off' }),
                      engaged
                        ? jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => setConfirming(card.shield_id), children: 'Turn off' })
                        : jsx('button', { type: 'button', className: 'bbx-cta', style: { margin: 0, padding: '10px 20px', fontSize: 14 }, onClick: () => setShield(card, true), children: `Engage ${card.name}` })
                    ]
                  })
                }),
                confirming === card.shield_id
                  ? jsxs('div', {
                      className: 'bbx-panel bbx-confirm',
                      children: [
                        jsx('span', { style: { flex: 1, minWidth: 220 }, children: `Turn off ${card.name}? Your agent could then read what it protects on this machine.` }),
                        jsx('button', {
                          type: 'button',
                          className: 'bbx-btn danger',
                          onClick: async () => {
                            setConfirming('')
                            await setShield(card, false)
                          },
                          children: 'Turn off'
                        }),
                        jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => setConfirming(''), children: 'Keep it on' })
                      ]
                    })
                  : null,
                jsx(ShieldStatus, { card }),
                card.shield_id === 'trader' && Object.keys(section).length ? jsx(TraderShieldSettings, { section }, JSON.stringify(section.mode)) : null
              ]
            }, card.shield_id)
          })
        })
      }
    })
  })
}


function Overview({ status, setTab, readiness, ctx }) {
  return jsxs('div', {
    className: 'bbx-wrap',
    style: { padding: 0 },
    children: [
      syncInProgress(readiness) ? jsx(FirstSyncBanner, { r: readiness, setTab, ctx }) : null,
      jsx(ConnectedAgents, {}),
      jsx(StatCards, { status }),
      jsx(ShieldBanner, { setTab })
    ]
  })
}


// ---------------------------------------------------------------- pop-ups

// One pop-up over the page, as the dashboard's modals: Escape or a click outside closes it, and the
// page underneath keeps its place (tab, page of a table, the map's zoom).
function Modal({ title, sub, tags, onClose, children }) {
  useEffect(() => {
    const onKey = event => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return jsx('div', {
    className: 'bbx-modal-backdrop',
    onMouseDown: event => {
      if (event.target === event.currentTarget) onClose()
    },
    children: jsxs('div', {
      className: 'bbx-modal',
      role: 'dialog',
      'aria-modal': 'true',
      children: [
        jsxs('div', {
          className: 'bbx-modal-head',
          children: [
            jsxs('div', {
              style: { minWidth: 0, flex: 1 },
              children: [
                tags ? jsx('div', { style: { display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }, children: tags }) : null,
                jsx('h2', { className: 'bbx-modal-title', children: title }),
                sub ? jsx('div', { className: 'bbx-small bbx-mono', style: { marginTop: 6, wordBreak: 'break-all' }, children: sub }) : null
              ]
            }),
            jsx('button', { type: 'button', className: 'bbx-iconbtn', title: 'Close (Esc)', onClick: onClose, children: jsx(Codicon, { name: 'close' }) })
          ]
        }),
        jsx('div', { className: 'bbx-modal-body', children })
      ]
    })
  })
}

// Label / value rows, the dashboard's detail grid. rows: [label, value, mono?]; empty values are skipped.
function DetailGrid({ rows }) {
  const shown = rows.filter(row => row[1] !== undefined && row[1] !== null && String(row[1]) !== '')
  if (!shown.length) return null
  return jsx('dl', {
    className: 'bbx-kv',
    children: shown.flatMap(([label, value, mono], index) => [
      jsx('dt', { children: label }, `t${index}`),
      jsx('dd', { className: mono ? 'bbx-mono' : '', children: String(value) }, `d${index}`)
    ])
  })
}

const TIER_NAMES = { public: 'Verifiable graph (VM)', community: 'Community graph (SWM)', local: 'Local graph (WM)' }
const fullDate = seconds => (typeof seconds === 'number' && seconds > 0 ? new Date(seconds * 1000).toLocaleString() : '')

// The fields the dashboard's threat pop-up shows for each kind of threat (index.html detailRows).
function threatRows(t) {
  const rows = []
  const type = t.category
  if (type === 'dependency') rows.push(['Ecosystem', t.ecosystem], ['Package', t.package, true], ['Version', t.version, true], ['Fixed in', t.fixed_version, true])
  else if (type === 'injection') rows.push(['OWASP', t.owasp], ['Pattern', t.pattern, true])
  else if (type === 'escalation') rows.push(['Tool', t.tool, true], ['Arg shape', t.arg_shape, true])
  else if (type === 'fileaccess') rows.push(['Tool', t.tool, true], ['File category', t.file_category])
  else if (type === 'ioc') rows.push(['Threat type', t.kind || t.reportReason], ['Indicator', t.iocType || t.ioc_type], ['Feed', t.sourceId])
  else if (type === 'skill') rows.push(['Skill', t.skill, true], ['Version', t.skill_version, true], ['Danger shape', t.danger_shape, true])
  rows.push(['Source', asList(t.sources).join('; ')], ['Contributor', t.contributor], ['Last updated', t.modified], ['Graph', TIER_NAMES[t.tier] || 'Threat graph'])
  if (t.tier === 'community') rows.push(['Stage', t.stage ? `${t.stage}${t.stageReason ? ` — ${t.stageReason}` : ''}` : ''])
  return rows
}

function threatTags(threat, t) {
  return [
    jsx(Pill, { tone: t.severity || threat.severity, children: cap(t.severity || threat.severity || 'unknown') }, 'severity'),
    jsx(TypeCell, { type: t.category || threat.category }, 'type'),
    t.curated ? jsx(Pill, { tone: 'ok', children: 'Verified' }, 'verified') : null
  ]
}

// The signed proof behind a community threat (GET /api/threat-proof), as the dashboard shows it.
function ThreatProof({ identifier }) {
  const query = useDash('threat-proof', `api/threat-proof?tier=community&identifier=${encodeURIComponent(identifier)}`, SLOW_POLL_MS)
  const proof = asObject(query.data)
  const reports = asList(proof.reports)
  if (query.isLoading || proof.error) return null
  return jsxs('div', {
    style: { display: 'flex', flexDirection: 'column', gap: 12 },
    children: [
      jsx('div', { className: 'bbx-label', children: 'Proof' }),
      reports.length
        ? reports.map((report, index) => jsx(DetailGrid, { rows: [['Signature', report.verified ? '✓ valid' : 'not checked'], ['Reported by', report.reporter, true], ['Signed by', report.signer, true], ['Fingerprint', report.fingerprint, true], ['Signed on', report.day]] }, index))
        : jsx('div', { className: 'bbx-small', children: 'No signed report for this threat has reached this node yet.' })
    ]
  })
}

function ThreatModal({ threat, onClose }) {
  const tier = threat.tier || 'public'
  const query = useDash('threat', `api/threat?identifier=${encodeURIComponent(threat.identifier)}&tier=${encodeURIComponent(tier)}`, SLOW_POLL_MS)
  const t = { tier, ...asObject(query.data) }
  return jsx(Modal, {
    title: t.name || threat.name || threat.identifier,
    sub: threat.identifier,
    tags: threatTags(threat, t),
    onClose,
    children: threat.local
      ? jsx(DetailGrid, { rows: [['Graph', TIER_NAMES.local], ['Seen on this machine', `${threat.count} time(s)`], ['Identifier', threat.identifier, true]] })
      : jsx(Loading, {
          query,
          children: () => {
            if (!t.found) return jsx('div', { className: 'bbx-empty', style: { padding: 0 }, children: 'This threat is not in the graph on this node.' })
            return jsxs('div', {
              style: { display: 'flex', flexDirection: 'column', gap: 18 },
              children: [
                t.description ? jsx('p', { style: { margin: 0, lineHeight: 1.6 }, children: t.description }) : null,
                jsx(DetailGrid, { rows: threatRows(t) }),
                asList(t.references).length
                  ? jsxs('div', { children: [jsx('div', { className: 'bbx-label', style: { marginBottom: 8 }, children: 'References' }), ...asList(t.references).map((ref, index) => jsx('div', { className: 'bbx-small bbx-mono', style: { wordBreak: 'break-all' }, children: ref }, index))] })
                  : null,
                tier === 'community' ? jsx(ThreatProof, { identifier: threat.identifier }) : null
              ]
            })
          }
        })
  })
}

// One finding from Threats detected: what happened here, and the matching threat in the verified graph.
function FindingModal({ row, onClose }) {
  const verified = useDash('threat', `api/threat?identifier=${encodeURIComponent(row.identifier || '')}&tier=public`, SLOW_POLL_MS)
  const t = asObject(verified.data)
  return jsx(Modal, {
    title: row.title || row.identifier || 'Threat',
    sub: row.identifier,
    tags: [
      jsx(Pill, { tone: row.severity, children: cap(row.severity || 'unknown') }, 'severity'),
      jsx(TypeCell, { type: row.category }, 'type'),
      jsx(Pill, { tone: row.decision === 'block' ? 'blocked' : 'neutral', children: row.decision === 'block' ? 'Blocked' : 'Flagged' }, 'outcome')
    ],
    onClose,
    children: jsxs('div', {
      style: { display: 'flex', flexDirection: 'column', gap: 18 },
      children: [
        jsx(DetailGrid, { rows: [['Time', fullDate(row.ts)], ['Agent', cap(row.framework || 'agent')], ['Tool', row.tool_name, true], ['Reasoning', row.evidence], ['Rule source', row.source], ['Session', row.session_id, true]] }),
        t.found
          ? jsxs('div', { style: { display: 'flex', flexDirection: 'column', gap: 12 }, children: [jsx('div', { className: 'bbx-label', children: 'In the verified threat graph' }), t.description ? jsx('p', { style: { margin: 0, lineHeight: 1.6 }, children: t.description }) : null, jsx(DetailGrid, { rows: threatRows({ tier: 'public', ...t }) })] })
          : null
      ]
    })
  })
}

// One row of Agent activity, with everything the dashboard's activity pop-up shows (index.html
// activityDetailBodyHTML) and the raw record. All of it stays on this machine.
function ActivityModal({ entry, onClose }) {
  const detail = asObject(entry.detail)
  const args = asObject(detail.args)
  const command = args.command || args.path || args.url || args.query || ''
  const pkg = entry.ecosystem || detail.ecosystem ? `${entry.ecosystem || detail.ecosystem}:${entry.name || detail.name || ''}@${entry.version || detail.version || ''}` : ''
  return jsx(Modal, {
    title: EVENT_LABELS[entry.event] || cap(entry.event || 'Activity'),
    sub: fullDate(entry.ts),
    onClose,
    children: jsxs('div', {
      style: { display: 'flex', flexDirection: 'column', gap: 18 },
      children: [
        jsx(DetailGrid, {
          rows: [
            ['Agent', cap(entry.framework || 'hermes')], ['Event', EVENT_LABELS[entry.event] || entry.event], ['Time', fullDate(entry.ts)],
            ['Session', detail.session_id, true], ['Tool', detail.tool_name, true], ['Command', command, true],
            ['Model', detail.model], ['Provider', detail.provider], ['Duration', detail.duration_ms != null ? `${detail.duration_ms} ms` : ''],
            ['Path', entry.path || detail.path, true], ['Mode', entry.mode || detail.mode], ['Package', pkg, true], ['Via', entry.tool || detail.tool, true]
          ]
        }),
        jsx('div', { className: 'bbx-label', children: 'Raw record' }),
        jsx('pre', { className: 'bbx-log', style: { maxHeight: 320 }, children: JSON.stringify(entry, null, 2) })
      ]
    })
  })
}

// ---------------------------------------------------------------- Threat graph tab

function SyncPanel() {
  const sync = useDash('sync', 'api/verified-sync', POLL_MS)
  return jsx('div', {
    className: 'bbx-panel',
    children: jsx(Loading, {
      query: sync,
      children: data => {
        const v = asObject(data)
        const percent = Math.round(typeof v.percent_compiled === 'number' ? v.percent_compiled : 0)
        const radius = 70
        const length = 2 * Math.PI * radius
        const bar = (label, done, total, pct) =>
          jsxs('div', {
            className: 'bbx-barrow',
            children: [
              jsx('span', { className: 'bbx-label', children: label }),
              jsx('div', { className: 'bbx-bar', children: jsx('i', { style: { width: `${Math.max(0, Math.min(100, pct || 0))}%` } }) }),
              jsx('span', { className: 'bbx-mono', style: { fontSize: 13 }, children: `${num(done)} / ${num(total)} · ${(pct || 0).toFixed(1)}%` })
            ]
          })
        return jsxs('div', {
          className: 'bbx-sync',
          children: [
            jsxs('svg', {
              viewBox: '0 0 180 180', width: 180, height: 180,
              children: [
                jsx('circle', { cx: 90, cy: 90, r: radius, fill: 'none', stroke: 'var(--bbx-hover)', strokeWidth: 12 }),
                jsx('circle', { cx: 90, cy: 90, r: radius, fill: 'none', stroke: '#3F8F5F', strokeWidth: 12, strokeDasharray: `${(percent / 100) * length} ${length}`, transform: 'rotate(-90 90 90)', strokeLinecap: 'round' }),
                jsx('text', { x: 90, y: 92, textAnchor: 'middle', fontSize: 34, fontWeight: 800, fill: 'currentColor', children: `${percent}%` }),
                jsx('text', { x: 90, y: 116, textAnchor: 'middle', fontSize: 10.5, letterSpacing: 2, fill: 'var(--bbx-muted)', fontFamily: 'ui-monospace, monospace', children: 'PROTECTED' })
              ]
            }),
            jsxs('div', {
              style: { display: 'flex', flexDirection: 'column', gap: 14 },
              children: [
                jsxs('div', { style: { display: 'flex', gap: 12, alignItems: 'center' }, children: [jsx('span', { style: { fontWeight: 700, fontSize: 17 }, children: 'Verified graph sync' }), jsx(Pill, { tone: v.state === 'synced' || percent >= 100 ? 'ok' : 'medium', children: String(v.state || (percent >= 100 ? 'synced' : 'syncing')).toUpperCase() })] }),
                v.phase_text ? jsx('div', { className: 'bbx-sub', style: { margin: 0 }, children: v.phase_text }) : null,
                asObject(v.lookups).text ? jsx('div', { className: 'bbx-ok', style: { fontFamily: 'inherit', fontWeight: 500 }, children: `✓ ${asObject(v.lookups).label || asObject(v.lookups).text}` }) : null,
                bar('Downloaded', v.downloaded_assets, v.graph_assets, v.percent_downloaded),
                bar('Compiled to rules', v.compiled_assets, v.graph_assets, v.percent_compiled),
                jsxs('div', {
                  className: 'bbx-facts',
                  children: [
                    jsxs('div', { children: [jsx('div', { className: 'bbx-label', children: 'Graph size' }), jsx('div', { className: 'bbx-fact-value', children: `${num(v.graph_assets)} assets` })] }),
                    jsxs('div', { children: [jsx('div', { className: 'bbx-label', children: 'Triples held' }), jsx('div', { className: 'bbx-fact-value', children: num(v.downloaded_triples) })] }),
                    jsxs('div', { children: [jsx('div', { className: 'bbx-label', children: 'Verified rules' }), jsx('div', { className: 'bbx-fact-value', children: num(v.verified_rules) })] })
                  ]
                })
              ]
            })
          ]
        })
      }
    })
  })
}

function FindThreat({ onOpen }) {
  const [search, setSearch] = useState('')
  const [term, setTerm] = useState('')
  const [page, setPage] = useState(0)
  const query = useDash('graph-search', term ? `api/graph?tier=public&limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}&q=${encodeURIComponent(term)}` : 'api/graph?tier=public&limit=1', SLOW_POLL_MS)
  return jsxs('div', {
    children: [
      jsxs('form', {
        className: 'bbx-searchbar',
        onSubmit: event => {
          event.preventDefault()
          setPage(0)
          setTerm(search.trim())
        },
        children: [
          jsx(Codicon, { name: 'search' }),
          jsx('input', { className: 'bbx-input', style: { flex: 1 }, placeholder: 'Find any threat in the verified graph: a package, domain, wallet or pattern', value: search, onChange: event => setSearch(event.target.value) }),
          term ? jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => { setSearch(''); setTerm('') }, children: 'Clear' }) : null,
          jsx('button', { type: 'submit', className: 'bbx-btn primary', children: 'Search' })
        ]
      }),
      term
        ? jsx(Loading, {
            query,
            empty: 'No threat matches that search.',
            children: data => {
              const result = asObject(data)
              const rows = asList(result.threats)
              if (!rows.length) return null
              const total = typeof result.total === 'number' ? result.total : rows.length
              return jsxs('div', {
                children: [
                  jsx('table', {
                    className: 'bbx-table',
                    children: jsx('tbody', {
                      children: rows.map(threat =>
                        jsxs('tr', { style: { cursor: 'pointer' }, onClick: () => onOpen({ ...threat, tier: 'public' }), children: [jsx('td', { style: { width: 120 }, children: jsx(Pill, { tone: threat.severity, children: cap(threat.severity) }) }), jsx('td', { style: { width: 200 }, children: jsx(TypeCell, { type: threat.category }) }), jsx('td', { children: threat.name || threat.identifier })] }, threat.identifier)
                      )
                    })
                  }),
                  jsx(Pager, { page, pages: Math.ceil(total / PAGE_SIZE), total, onPage: setPage })
                ]
              })
            }
          })
        : null
    ]
  })
}

function reasonOf(row) {
  const lines = [row.evidence || row.title || row.identifier, [row.title, row.tool_name && `via ${row.tool_name}`].filter(Boolean).join(' · ')]
  return jsxs('div', { children: [jsx('div', { className: 'bbx-mono', style: { fontSize: 13 }, children: lines[0] }), lines[1] ? jsx('div', { className: 'bbx-small bbx-mono', children: lines[1] }) : null] })
}

function ThreatsDetected() {
  const [shown, setShown] = useState(null)
  const [order, setOrder] = useState('newest')
  const [page, setPage] = useState(0)
  const query = useDash('findings-all', 'api/findings?limit=500', POLL_MS)
  return jsxs('section', {
    className: 'bbx-section',
    children: [
      jsx(Heading, {
        title: jsxs('span', { style: { display: 'inline-flex', gap: 12, alignItems: 'center' }, children: [jsx('span', { style: { color: SIGNAL }, children: jsx(Codicon, { name: 'warning', size: '22px' }) }), 'Threats detected'] }),
        actions: jsxs('div', { style: { display: 'flex', gap: 10, alignItems: 'center' }, children: [jsx('span', { className: 'bbx-label', children: 'Sort' }), jsx(Segmented, { value: order, options: [['newest', 'Newest'], ['severity', 'Severity']], onChange: value => { setOrder(value); setPage(0) } })] })
      }),
      jsx('div', {
        className: 'bbx-panel',
        children: jsx(Loading, {
          query,
          empty: 'No threats detected yet. Blackbox is watching every tool call your agents make.',
          children: data => {
            const rows = asList(asObject(data).findings).slice()
            if (!rows.length) return null
            if (order === 'severity') rows.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0) || (b.ts || 0) - (a.ts || 0))
            const pages = Math.ceil(rows.length / PAGE_SIZE)
            const current = Math.min(page, pages - 1)
            return jsxs('div', {
              children: [
                jsxs('table', {
                  className: 'bbx-table',
                  children: [
                    jsx('thead', { children: jsxs('tr', { children: [jsx('th', { children: 'Time' }), jsx('th', { children: 'Agent' }), jsx('th', { children: 'Severity' }), jsx('th', { children: 'Type' }), jsx('th', { children: 'Reasoning' }), jsx('th', { children: 'Outcome' })] }) }),
                    jsx('tbody', {
                      children: rows.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE).map((row, index) =>
                        jsxs('tr', {
                          className: 'bbx-row-open',
                          title: 'Open this threat',
                          onClick: () => setShown(row),
                          children: [
                            jsx('td', { style: { width: 130 }, children: timeCell(row.ts) }),
                            jsx('td', { style: { width: 110 }, children: jsx('span', { style: { color: '#3FA568', fontFamily: 'var(--bbx-mono)' }, children: cap(row.framework || 'agent') }) }),
                            jsx('td', { style: { width: 110 }, children: jsx(Pill, { tone: row.severity, children: cap(row.severity || 'unknown') }) }),
                            jsx('td', { style: { width: 180 }, children: jsx(TypeCell, { type: row.category }) }),
                            jsx('td', { children: reasonOf(row) }),
                            jsx('td', { style: { width: 100 }, children: jsx(Pill, { tone: row.decision === 'block' ? 'blocked' : 'neutral', children: row.decision === 'block' ? 'Blocked' : 'Flagged' }) })
                          ]
                        }, `${row.ts}-${index}`)
                      )
                    })
                  ]
                }),
                jsx(Pager, { page: current, pages, total: rows.length, onPage: setPage })
              ]
            })
          }
        })
      }),
      shown ? jsx(FindingModal, { row: shown, onClose: () => setShown(null) }) : null
    ]
  })
}

function activityDetails(entry) {
  const detail = asObject(entry.detail)
  const args = asObject(detail.args)
  let main = ''
  if (entry.event === 'file_access') main = `${entry.mode || 'read'} ${entry.path || ''}`
  else if (entry.event === 'dependency_install') main = `${entry.ecosystem ? entry.ecosystem + ':' : ''}${entry.name || ''}${entry.version ? '@' + entry.version : ''}`
  else if (entry.event === 'flagged' || entry.event === 'blocked') main = asObject(entry.finding).title || asObject(entry.finding).identifier || 'Threat'
  else if (entry.event && entry.event.startsWith('session')) main = `session ${String(detail.session_id || '').replace(/^local-/, '').slice(0, 6)}`
  else main = String(args.command || args.path || args.url || args.query || detail.tool_name || entry.tool || '').slice(0, 180)
  const via = entry.tool || detail.tool_name
  return jsxs('div', { children: [jsx('div', { className: 'bbx-mono', style: { fontSize: 13, wordBreak: 'break-word' }, children: main || EVENT_LABELS[entry.event] || entry.event }), via ? jsx('div', { className: 'bbx-small bbx-mono', children: `via ${via}` }) : null] })
}

function AgentActivity() {
  const [shown, setShown] = useState(null)
  const [filter, setFilter] = useState('all')
  const [page, setPage] = useState(0)
  const query = useDash('audit-all', 'api/audit?limit=500', POLL_MS)
  return jsxs('section', {
    className: 'bbx-section',
    children: [
      jsx(Heading, {
        title: 'Agent activity',
        sub: 'Recorded sessions, API calls, tool calls and installs.',
        actions: jsx(Segmented, { value: filter, options: [['all', 'All activity'], ['threats', 'Threats only']], onChange: value => { setFilter(value); setPage(0) } })
      }),
      jsx('div', {
        className: 'bbx-panel',
        children: jsx(Loading, {
          query,
          empty: 'No activity recorded yet.',
          children: data => {
            const all = asList(asObject(data).entries)
            const rows = filter === 'threats' ? all.filter(entry => entry.event === 'flagged' || entry.event === 'blocked' || (entry.severity && entry.severity !== 'info')) : all
            if (!rows.length) return null
            const pages = Math.ceil(rows.length / PAGE_SIZE)
            const current = Math.min(page, pages - 1)
            return jsxs('div', {
              children: [
                jsxs('table', {
                  className: 'bbx-table',
                  children: [
                    jsx('thead', { children: jsxs('tr', { children: [jsx('th', { children: 'Time' }), jsx('th', { children: 'Agent' }), jsx('th', { children: 'Event' }), jsx('th', { children: 'Details' })] }) }),
                    jsx('tbody', {
                      children: rows.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE).map((entry, index) =>
                        jsxs('tr', {
                          className: 'bbx-row-open',
                          title: 'Open this activity',
                          onClick: () => setShown(entry),
                          children: [
                            jsx('td', { style: { width: 130 }, children: timeCell(entry.ts) }),
                            jsx('td', { style: { width: 110 }, children: cap(entry.framework || 'agent') }),
                            jsx('td', { style: { width: 170 }, children: jsx(Pill, { tone: entry.event === 'blocked' ? 'blocked' : entry.event === 'flagged' ? entry.severity || 'high' : 'neutral', children: EVENT_LABELS[entry.event] || entry.event }) }),
                            jsx('td', { children: activityDetails(entry) })
                          ]
                        }, `${entry.ts}-${index}`)
                      )
                    })
                  ]
                }),
                jsx(Pager, { page: current, pages, total: rows.length, onPage: setPage })
              ]
            })
          }
        })
      }),
      shown ? jsx(ActivityModal, { entry: shown, onClose: () => setShown(null) }) : null
    ]
  })
}

function ThreatGraphTab({ readiness }) {
  const [tier, setTier] = useState('public')
  const [open, setOpen] = useState(null)
  const status = useDash('graph-status', 'api/graph-status')
  const community = useDash('community-stats', 'api/community-stats')
  // A sample of each threat type, asked for separately: the graph lists one type after another, so a
  // single page of the verified tier held no indicators at all (717,005 of them, 2026-11-06).
  const map = useQuery({
    queryKey: ['blackbox', 'dash', 'graph-map', tier],
    refetchInterval: SLOW_POLL_MS,
    placeholderData: previous => previous, // the last graph stays up while the next tier loads
    queryFn: async () => {
      if (tier === 'local') return { ...asObject(await dash('api/findings?limit=500')), loadedTier: tier }
      const first = await dash(`api/graph?tier=${tier}&limit=${LEAVES_PER_TYPE}`)
      const totals = asObject(asObject(first).category_totals)
      const types = Object.keys(totals).filter(type => totals[type] > 0)
      if (types.length === 0) return { ...asObject(first), loadedTier: tier }
      const ecosystems = Object.keys(asObject(asObject(first).ecosystem_totals))
      const pages = await Promise.all([
        ...types.filter(type => type !== 'dependency' || ecosystems.length < 2)
          .map(type => dash(`api/graph?tier=${tier}&limit=${LEAVES_PER_TYPE}&category=${encodeURIComponent(type)}`)),
        ...(types.includes('dependency') && ecosystems.length > 1
          ? ecosystems.map(ecosystem => dash(`api/graph?tier=${tier}&limit=${LEAVES_PER_TYPE}&category=dependency&ecosystem=${encodeURIComponent(ecosystem)}`))
          : [])
      ])
      return { ...asObject(first), threats: pages.flatMap(page => asList(asObject(page).threats)), loadedTier: tier }
    }
  })
  const mapData = asObject(map.data)
  const tierLabel = { public: 'Verified', community: 'Community', local: 'Local' }[tier]
  // drawn from the tier the data belongs to: while the next tier loads, the last graph stays as it was
  const graph = useMemo(() => {
    const shown = mapData.loadedTier || tier
    const threats = shown === 'local' ? localThreats(asList(mapData.findings)) : asList(mapData.threats).map(threat => ({ ...threat, tier: shown }))
    const totals = shown === 'local' ? {} : asObject(mapData.category_totals)
    const ecosystemTotals = shown === 'local' ? {} : asObject(mapData.ecosystem_totals)
    const label = { public: 'Verifiable graph', community: 'Community graph', local: 'Local graph' }[shown]
    return threats.length ? buildBubbleGraph(label, threats, totals, ecosystemTotals) : null
  }, [map.dataUpdatedAt, mapData.loadedTier])
  const syncNow = async () => {
    const answer = await dash('api/sync', { method: 'POST', body: {} })
    host.notify(answer && answer.ok ? { kind: 'success', message: answer.busy ? 'A sync is already running' : 'Sync started' } : { kind: 'error', message: 'Could not start a sync' })
    refreshDash()
  }
  const g = asObject(status.data)
  const counts = { public: g.curated, community: asObject(community.data).community_threats ?? g.community, local: g.findings_logged }
  const subtitles = {
    public: 'Threats verified by Umanitek. A verified rule may block.',
    community: 'Threats reported by other Blackbox nodes. They only ever flag.',
    local: 'Threats Blackbox found on this machine.'
  }
  return jsxs('div', {
    className: 'bbx-wrap',
    style: { padding: 0 },
    children: [
      jsxs('section', {
        className: 'bbx-section',
        children: [
          jsx(Heading, {
            title: 'Threat graph',
            sub: subtitles[tier],
            actions: jsxs('div', {
              style: { display: 'flex', gap: 10, alignItems: 'center' },
              children: [
                jsxs('div', {
                  className: 'bbx-tabs',
                  children: [['public', 'Verifiable'], ['community', 'Community'], ['local', 'Local']].map(([id, label]) =>
                    jsxs('button', { type: 'button', className: 'bbx-tab', 'aria-selected': tier === id ? 'true' : 'false', onClick: () => setTier(id), children: [label, jsx('span', { className: 'bbx-tab-count', children: typeof counts[id] === 'number' ? counts[id].toLocaleString() : '–' })] }, id)
                  )
                }),
                jsx('button', { type: 'button', className: 'bbx-iconbtn', title: 'Sync the verified graph now', onClick: syncNow, children: jsx(Codicon, { name: 'refresh' }) })
              ]
            })
          }),
          jsx(SyncPanel, {}),
          jsxs('div', {
            className: 'bbx-panel bbx-graphwrap',
            children: [
              jsx(FindThreat, { onOpen: setOpen }),
              jsx(Loading, {
                query: map,
                empty: readiness.stage === 'syncing' && tier === 'public'
                  ? 'The verified map draws itself as the first sync brings threats in; the sync above shows how far it is.'
                  : `No ${tierLabel.toLowerCase()} threats to draw yet.`,
                children: () => (graph ? jsx(BubbleMap, { graph, loading: map.isPlaceholderData, onPick: threat => setOpen(threat) }) : null)
              })
            ]
          })
        ]
      }),
      jsx(ThreatsDetected, {}),
      jsx(AgentActivity, {}),
      open ? jsx(ThreatModal, { threat: open, onClose: () => setOpen(null) }) : null
    ]
  })
}

// ---------------------------------------------------------------- Settings tab

function SettingRow({ title, help, children }) {
  return jsxs('div', {
    className: 'bbx-setrow',
    children: [jsxs('div', { className: 'bbx-setrow-text', children: [jsx('div', { className: 'bbx-setrow-title', children: title }), help ? jsx('div', { className: 'bbx-small', children: help }) : null] }), children]
  })
}

function SeverityPick({ value, onChange }) {
  return jsx('select', {
    className: 'bbx-select',
    value: SEVERITIES.includes(value) ? value : 'info',
    onChange: event => onChange(event.target.value),
    children: SEVERITIES.map(name => jsx('option', { value: name, children: cap(name) }, name))
  })
}

function ProtectionSettings({ initial }) {
  const [state, setState] = useState(() => ({
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
    const ok = await saveSettings(
      {
        mode: initial.mode === 'block' ? 'block' : 'audit', // the mode changes only through the Mode switch above
        report: !!initial.report, // sharing changes only below, with its consent step
        block_severity: state.block_severity,
        report_min_severity: state.report_min_severity,
        discover: state.discover,
        osv_lookup: state.osv_lookup,
        community_sandbox: state.community_sandbox,
        categories: state.categories,
        protected_paths: state.protected_paths.slice(0, 100)
      },
      'Settings saved.'
    )
    if (ok) setDirty(false)
  }
  return jsxs('section', {
    className: 'bbx-section',
    children: [
      jsx(Heading, { title: 'Protection', sub: 'What Blackbox checks, and what it refuses in block mode.' }),
      jsxs('div', {
        className: 'bbx-panel',
        children: [
          jsx(SettingRow, { title: 'Lowest severity blocked', help: 'In block mode, verified threats at or above this severity are refused.', children: jsx(SeverityPick, { value: state.block_severity, onChange: value => set('block_severity', value) }) }),
          jsx(SettingRow, { title: 'Lowest severity flagged', help: 'A built-in check must reach this severity to be flagged or shared.', children: jsx(SeverityPick, { value: state.report_min_severity, onChange: value => set('report_min_severity', value) }) }),
          ...Object.keys(state.categories).map(key =>
            jsx(
              SettingRow,
              {
                title: labels[key] || key,
                help: 'Flag from',
                children: jsxs('div', { style: { display: 'flex', gap: 14, alignItems: 'center' }, children: [jsx(SeverityPick, { value: asObject(state.categories[key]).min_severity, onChange: value => setCategory(key, 'min_severity', value) }), jsx(Switch, { checked: asObject(state.categories[key]).enabled, label: labels[key] || key, onChange: value => setCategory(key, 'enabled', value) })] })
              },
              key
            )
          ),
          jsxs('div', {
            className: 'bbx-setrow',
            style: { flexDirection: 'column', alignItems: 'stretch' },
            children: [
              jsxs('div', { children: [jsx('div', { className: 'bbx-setrow-title', children: 'Protected paths' }), jsx('div', { className: 'bbx-small', children: 'Files and folders an agent may not read or copy, one per line. In block mode a match is refused; these rules never leave this machine.' })] }),
              jsx('textarea', { className: 'bbx-textarea', value: state.protected_paths.join('\n'), onChange: event => set('protected_paths', event.target.value.split('\n').map(line => line.trim()).filter(Boolean)) })
            ]
          }),
          jsx(SettingRow, { title: 'Look packages up on OSV.dev', help: 'Sends the package name and version, never your code.', children: jsx(Switch, { checked: state.osv_lookup, label: 'OSV lookup', onChange: value => set('osv_lookup', value) }) }),
          jsx(SettingRow, { title: 'Built-in checks', help: 'Flag threats not in the graph yet (flag only, never block).', children: jsx(Switch, { checked: state.discover, label: 'Built-in checks', onChange: value => set('discover', value) }) }),
          jsx(SettingRow, { title: 'Sandbox mode', help: 'Playground tests go to a test lane, never the real community graph.', children: jsx(Switch, { checked: state.community_sandbox, label: 'Sandbox mode', onChange: value => set('community_sandbox', value) }) }),
          jsxs('div', { className: 'bbx-savebar', children: [jsx('button', { type: 'button', className: 'bbx-btn primary', disabled: !dirty, onClick: save, children: 'Save protection settings' }), dirty ? jsx('span', { className: 'bbx-small', children: 'Unsaved changes' }) : null] })
        ]
      })
    ]
  })
}

function TraderShieldSettings({ section }) {
  const mode = asObject(section.mode)
  const [draft, setDraft] = useState(null)
  const value = draft || { enabled: !!mode.enabled, wallets: asList(mode.wallets), addresses: asList(mode.addresses) }
  const change = (key, next) => setDraft({ ...value, [key]: next })
  const save = async () => {
    const ok = await saveSettings({ shields: { trader: value } }, 'Trader Shield saved. Restart your agent so it picks the change up.')
    if (ok) setDraft(null)
  }
  return jsxs('section', {
    className: 'bbx-section',
    children: [
      jsx(Heading, { title: 'Settings', sub: 'Which wallets and addresses Trader Shield guards.' }),
      jsxs('div', {
        className: 'bbx-panel',
        children: [
          ...asList(section.fields).map(field => {
            if (field.kind === 'toggle')
              return jsx(SettingRow, { title: field.label, help: field.help, children: jsx(Switch, { checked: !!value[field.key], label: field.label, onChange: next => change(field.key, next) }) }, field.key)
            if (field.kind === 'multi-pick') {
              const chosen = new Set(asList(value[field.key]))
              return jsxs(
                'div',
                {
                  className: 'bbx-setrow',
                  style: { flexDirection: 'column', alignItems: 'stretch' },
                  children: [
                    jsxs('div', { children: [jsx('div', { className: 'bbx-setrow-title', children: field.label }), field.help ? jsx('div', { className: 'bbx-small', children: field.help }) : null] }),
                    jsx('div', {
                      style: { display: 'flex', flexWrap: 'wrap', gap: 8 },
                      children: asList(field.options).map(option =>
                        jsx('button', {
                          type: 'button', className: 'bbx-btn', 'aria-pressed': chosen.has(option.id) ? 'true' : 'false',
                          style: chosen.has(option.id) ? { borderColor: '#3F8F5F', color: '#3FA568' } : undefined,
                          onClick: () => {
                            const next = new Set(chosen)
                            if (next.has(option.id)) next.delete(option.id)
                            else next.add(option.id)
                            change(field.key, Array.from(next))
                          },
                          children: `${chosen.has(option.id) ? '✓ ' : ''}${option.name}${option.status && option.status !== 'supported' ? ` (${option.status})` : ''}`
                        }, option.id)
                      )
                    })
                  ]
                },
                field.key
              )
            }
            if (field.kind === 'lines')
              return jsxs(
                'div',
                {
                  className: 'bbx-setrow',
                  style: { flexDirection: 'column', alignItems: 'stretch' },
                  children: [
                    jsxs('div', { children: [jsx('div', { className: 'bbx-setrow-title', children: field.label }), field.help ? jsx('div', { className: 'bbx-small', children: field.help }) : null] }),
                    jsx('textarea', { className: 'bbx-textarea', style: { minHeight: 70 }, value: asList(value[field.key]).join('\n'), onChange: event => change(field.key, event.target.value.split('\n').map(line => line.trim()).filter(Boolean)) })
                  ]
                },
                field.key
              )
            return null
          }),
          jsxs('div', { className: 'bbx-savebar', children: [jsx('button', { type: 'button', className: 'bbx-btn primary', disabled: !draft, onClick: save, children: 'Save Trader Shield' }), draft ? jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => setDraft(null), children: 'Discard' }) : null] })
        ]
      })
    ]
  })
}

function CommunitySettings({ sharing }) {
  const community = useDash('community-stats', 'api/community-stats')
  const trust = useDash('trust', 'api/trust')
  const [confirming, setConfirming] = useState(false)
  const c = asObject(community.data)
  const t = asObject(trust.data)
  const setSharing = async on => {
    setConfirming(false)
    await saveSettings({ report: on }, on ? 'Sharing is on. You agreed to the reporter terms.' : 'Sharing is off.')
  }
  return jsxs('section', {
    className: 'bbx-section',
    children: [
      jsx(Heading, { title: 'Community graph', sub: 'Other Blackbox nodes report threats to one shared graph; their reports only ever flag. Your node reads them either way.' }),
      jsxs('div', {
        className: 'bbx-panel',
        children: [
          jsx(SettingRow, { title: 'Membership', help: c.admission_text || '', children: jsx('span', { className: 'bbx-ok', children: c.join_text || c.join_state || '–' }) }),
          jsx(SettingRow, {
            title: 'Share threat reports',
            help: 'Privacy-safe, signed reports: the threat’s name, category, severity and the day — never prompts, commands, file contents or secrets.',
            children: jsx(Switch, { checked: sharing, label: 'Share threat reports', onChange: on => (on ? setConfirming(true) : setSharing(false)) })
          }),
          confirming
            ? jsxs('div', {
                className: 'bbx-confirm',
                children: [
                  jsx('span', { style: { flex: 1, minWidth: 260 }, children: 'Turning sharing on records your agreement to the reporter terms (blackbox report --consent shows them).' }),
                  jsx('button', { type: 'button', className: 'bbx-btn primary', onClick: () => setSharing(true), children: 'I agree, turn sharing on' }),
                  jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => setConfirming(false), children: 'Cancel' })
                ]
              })
            : null,
          ...asList(t.authorities).map((authority, index) =>
            jsx(SettingRow, { title: `${cap(authority.authority)} authority`, help: `${authority.threshold || '?'} of ${authority.keys || '?'} curators sign its statements`, children: jsx(Pill, { tone: authority.trusted ? 'ok' : 'neutral', children: authority.trusted ? 'Trusted' : cap(authority.state || 'not trusted') }) }, `a${index}`)
          )
        ]
      })
    ]
  })
}

function SettingsTab() {
  const query = useDash('settings', 'api/settings')
  return jsx('div', {
    className: 'bbx-wrap',
    style: { padding: 0 },
    children: jsx(Loading, {
      query,
      children: data => {
        const settings = asObject(data)
        return jsxs('div', {
          style: { display: 'flex', flexDirection: 'column', gap: 40 },
          children: [
            jsxs('section', { className: 'bbx-section', children: [jsx(Heading, { title: 'Mode', sub: 'Audit records what agents do; Block also stops threats.' }), jsx(ModeCard, { mode: settings.mode === 'block' ? 'block' : 'audit', blockSeverity: settings.block_severity })] }),
            // keyed by what was saved, so a change made elsewhere (the switch, the dashboard) reloads the form
            jsx(ProtectionSettings, { initial: settings }, JSON.stringify([settings.block_severity, settings.report_min_severity, settings.categories, settings.protected_paths])),
            jsx(CommunitySettings, { sharing: !!settings.report })
          ]
        })
      }
    })
  })
}

// ---------------------------------------------------------------- getting ready (setup → first sync)

// Where this machine is between plugin install and synced, from Blackbox's own /readiness route
// (desktop/readiness.py decides the stage): setup-needed → installing (or setup-failed) → starting →
// syncing (the first sync) → ready. Polled fast while something is moving, like the dashboard.
const READINESS_KEY = ['blackbox', 'readiness']
const READINESS_POLL_MS = { installing: 2000, starting: 2000, 'setup-needed': 8000, 'setup-failed': 8000, syncing: POLL_MS, ready: SLOW_POLL_MS }
const SETUP_SCREEN_STAGES = ['setup-needed', 'installing', 'setup-failed', 'starting']
const SETUP_COMMAND = 'hermes blackbox setup'
// What setup does to this machine, said before the button (the catalog's own disclosure, in plain words).
const SETUP_DISCLOSURE = [
  ['package', 'Installs the OriginTrail DKG node from npm, checksum-verified, with a local graph store (Oxigraph, or Blazegraph when Docker runs). Node.js too, if it is missing.'],
  ['globe', "Joins the DKG peer-to-peer network to download Umanitek's verified threat graph: about 30 minutes and up to 8 GB of disk the first time."],
  ['play-circle', 'Starts the node and the Blackbox dashboard (127.0.0.1:9700) now and at every login.'],
  ['lock', 'Threat sharing stays off until you turn it on. Nothing leaves this machine before that.']
]

const fetchReadiness = () => (rest ? rest('/readiness') : Promise.resolve({ available: false }))

function useReadiness() {
  return useQuery({
    queryKey: READINESS_KEY,
    queryFn: fetchReadiness,
    refetchInterval: query => {
      const r = asObject(query.state.data)
      return syncInProgress(r) ? POLL_MS : READINESS_POLL_MS[r.stage] || POLL_MS
    }
  })
}

function duration(fromSeconds) {
  if (typeof fromSeconds !== 'number' || fromSeconds <= 0) return ''
  const total = Math.max(0, Math.round(Date.now() / 1000 - fromSeconds))
  const minutes = Math.floor(total / 60)
  return minutes > 0 ? `${minutes}m ${String(total % 60).padStart(2, '0')}s` : `${total}s`
}

function CopyCommand({ text }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    const done = () => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    }
    try {
      navigator.clipboard.writeText(text).then(done, () => host.notify({ kind: 'warning', message: `Copy this: ${text}` }))
    } catch (error) {
      host.notify({ kind: 'warning', message: `Copy this: ${text}` })
    }
  }
  return jsxs('div', {
    className: 'bbx-cmd',
    children: [
      jsx('span', { className: 'bbx-cmd-prompt', children: '$' }),
      jsx('code', { children: text }),
      jsx('button', { type: 'button', className: 'bbx-btn', onClick: copy, children: copied ? 'Copied' : 'Copy' })
    ]
  })
}

function StepMark({ state, number }) {
  if (state === 'done') return jsx('span', { className: 'bbx-stepmark done', children: jsx(Codicon, { name: 'check' }) })
  if (state === 'failed') return jsx('span', { className: 'bbx-stepmark failed', children: jsx(Codicon, { name: 'close' }) })
  if (state === 'active') return jsx('span', { className: 'bbx-stepmark active', children: jsx('span', { className: 'bbx-spin' }) })
  return jsx('span', { className: 'bbx-stepmark', children: String(number) })
}

// Setup's own steps (from the installer's section headings) and, last, the first sync.
function readySteps(r) {
  const steps = asList(r.steps).map(step => ({ ...step }))
  const sync = asObject(r.sync)
  const syncState = r.stage === 'ready' ? 'done' : r.stage === 'syncing' ? 'active' : 'waiting'
  const percent = typeof sync.percent === 'number' ? ` · ${sync.percent.toFixed(1)}%` : ''
  steps.push({ id: 'sync', label: 'Download the verified threat graph', state: syncState, detail: syncState === 'active' ? `${sync.phaseText || 'Starting the first sync.'}${percent}` : '' })
  return steps
}

function SetupSteps({ r }) {
  const [showLog, setShowLog] = useState(r.stage === 'setup-failed')
  const steps = readySteps(r)
  const done = steps.filter(step => step.state === 'done').length
  const setup = asObject(r.setup)
  const lines = asList(setup.logTail)
  return jsxs('div', {
    className: 'bbx-panel bbx-stepper',
    children: [
      jsx('div', { className: 'bbx-progress', children: jsx('i', { style: { width: `${Math.round((done / steps.length) * 100)}%` } }) }),
      jsxs('div', {
        className: 'bbx-stepper-head',
        children: [
          jsx('span', { className: 'bbx-label', children: `${done} of ${steps.length} done` }),
          jsx('div', { className: 'bbx-spacer' }),
          setup.state === 'running' && setup.started ? jsx('span', { className: 'bbx-label', children: duration(setup.started) }) : null
        ]
      }),
      jsx('ol', {
        className: 'bbx-steps',
        children: steps.map((step, index) =>
          jsxs('li', {
            className: `bbx-step ${step.state}`,
            children: [
              jsx(StepMark, { state: step.state, number: index + 1 }),
              jsxs('div', { children: [jsx('div', { className: 'bbx-step-label', children: step.label }), step.detail ? jsx('div', { className: 'bbx-step-detail', children: step.detail }) : null] })
            ]
          }, step.id)
        )
      }),
      lines.length
        ? jsxs('div', {
            className: 'bbx-logwrap',
            children: [
              jsxs('button', { type: 'button', className: 'bbx-linkbtn', onClick: () => setShowLog(!showLog), children: [jsx(Codicon, { name: showLog ? 'chevron-down' : 'chevron-right' }), showLog ? 'Hide details' : 'Show details'] }),
              showLog ? jsx('pre', { className: 'bbx-log', children: lines.join('\n') }) : null
            ]
          })
        : null
    ]
  })
}

async function startSetup() {
  try {
    const answer = await rest('/setup', { method: 'POST', body: {} })
    if (!answer || answer.started !== true) host.notify({ kind: 'warning', message: `Setup did not start: ${(answer && (answer.reason || answer.error)) || 'unknown reason'}` })
  } catch (error) {
    host.notify({ kind: 'error', message: `Setup did not start: ${String((error && error.message) || error)}` })
  }
  queryClient.invalidateQueries({ queryKey: READINESS_KEY })
}

const SETUP_COPY = {
  'setup-needed': {
    kicker: 'One last step',
    title: 'Finish setting up Blackbox',
    sub: "The plugin is installed and its built-in rules already protect your agent: protected files, secrets and Trader Shield. Setup adds the local threat-graph node, so every action is also checked against Umanitek's verified threat graph."
  },
  installing: {
    kicker: 'Setting up',
    title: 'Setting up Blackbox',
    sub: 'This takes a few minutes. Keep using Hermes; setup carries on if you leave this page, and the built-in rules protect your agent meanwhile.'
  },
  'setup-failed': {
    kicker: 'Setup stopped',
    title: 'Setup did not finish',
    sub: 'Setup undoes its own changes when it stops, so it is safe to run again. The details below say where it stopped.'
  },
  starting: {
    kicker: 'Starting',
    title: 'Starting the threat-graph node',
    sub: 'Blackbox is installed and its node is starting. This usually takes under a minute.'
  }
}

function GettingReady({ r }) {
  const [starting, setStarting] = useState(false)
  const copy = SETUP_COPY[r.stage] || SETUP_COPY['setup-needed']
  const offerSetup = r.stage === 'setup-needed' || r.stage === 'setup-failed'
  const error = asObject(r.setup).error
  const run = async () => {
    setStarting(true)
    await startSetup()
    setStarting(false)
  }
  return jsxs('div', {
    className: 'bbx-ready',
    children: [
      jsxs('div', {
        className: 'bbx-ready-main',
        children: [
          jsx('div', { className: 'bbx-kicker', children: copy.kicker }),
          jsx('h1', { className: 'bbx-hero', children: copy.title }),
          jsx('p', { className: 'bbx-hero-sub', children: copy.sub }),
          r.stage === 'setup-failed' && error ? jsx('div', { className: 'bbx-alert', children: error }) : null,
          jsxs('div', {
            className: 'bbx-shieldnote',
            children: [jsx(Codicon, { name: 'shield' }), jsx('span', { children: 'Protected now by the built-in rules. Verified threat-graph checks switch on as the graph arrives.' })]
          }),
          offerSetup
            ? jsxs('div', {
                className: 'bbx-ready-actions',
                children: [
                  jsx('button', { type: 'button', className: 'bbx-cta', disabled: starting, onClick: run, children: starting ? 'Starting…' : r.stage === 'setup-failed' ? 'Run setup again' : 'Set up Blackbox' }),
                  jsx('div', { className: 'bbx-small', children: 'Prefer a terminal? Run this instead:' }),
                  jsx(CopyCommand, { text: SETUP_COMMAND })
                ]
              })
            : null,
        ]
      }),
      r.stage === 'setup-needed' ? jsx(SetupPreview, {}) : jsx(SetupSteps, { r })
    ]
  })
}

// Before setup starts: what clicking the button will do — a plain list, never a progress list that
// reads as something already running.
function SetupPreview() {
  return jsxs('div', {
    className: 'bbx-panel bbx-preview',
    children: [
      jsx('div', { className: 'bbx-label', children: 'What happens when you click Set up' }),
      ...SETUP_DISCLOSURE.map(([icon, text]) => jsxs('div', { className: 'bbx-disclose-row', children: [jsx(Codicon, { name: icon }), jsx('span', { children: text })] }, icon)),
      jsx('div', { className: 'bbx-small', children: 'It takes a few minutes; you watch each step here as it happens, and this page switches to Blackbox by itself when setup is done.' })
    ]
  })
}

// The sync meter's phases while the graph is still arriving (dashboard/sync_meter/progress.py sync_phase).
const SYNC_MOVING_PHASES = ['finding', 'queued', 'downloading', 'compiling', 'stalled']
// Whether Overview shows the sync banner: the first sync before any rule, and every sync the meter
// says is still arriving — protection starts with the first rules, the graph keeps coming.
const syncInProgress = r => r.stage === 'syncing' || SYNC_MOVING_PHASES.includes(asObject(r.sync).phase)

// Overview's banner while the verified graph arrives: live phase, percentage and counts, every few seconds.
function FirstSyncBanner({ r, setTab, ctx }) {
  const sync = asObject(r.sync)
  const percent = typeof sync.percent === 'number' ? sync.percent : null
  const countText = typeof sync.total === 'number' && sync.total > 0 ? `${num(sync.downloaded)} of ${num(sync.total)} graph assets` : ''
  // the meter's own sentence may already carry the counts ("Downloading verified assets: 70 of 974.")
  const phaseHasCounts = [` of ${sync.total}`, ` of ${num(sync.total)}`].some(text => String(sync.phaseText || '').includes(text))
  const counts = countText && !phaseHasCounts ? countText : ''
  const rules = typeof r.rules === 'number' ? r.rules : 0
  const stalled = sync.phase === 'stalled'
  const kicker = stalled ? 'Sync stopped making progress' : rules > 0 ? 'Still syncing' : 'First sync in progress'
  const note = stalled
    ? 'Blackbox keeps protecting with what it has. Check the node with blackbox status, then run blackbox sync --wait.'
    : rules > 0
      ? `${num(rules)} verified rules protect you now; more switch on as the rest of the graph arrives. You can close this page.`
      : 'You are protected by the built-in rules now; verified checks switch on as the rules compile. About 30 minutes on a new machine. You can close this page.'
  return jsxs('div', {
    className: 'bbx-panel bbx-syncbanner',
    children: [
      jsxs('div', {
        className: 'bbx-syncbanner-ring',
        children: [jsx('span', { className: 'bbx-spin big' }), jsx('span', { className: 'bbx-mono', children: percent === null ? '…' : `${Math.round(percent)}%` })]
      }),
      jsxs('div', {
        style: { flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 8 },
        children: [
          jsx('div', { className: 'bbx-label', style: { color: stalled ? '#E5A00D' : 'var(--bbx-signal)' }, children: kicker }),
          jsx('div', { style: { fontSize: 17, fontWeight: 700 }, children: "Loading Umanitek's verified threat graph" }),
          jsx('div', { className: 'bbx-small', children: [sync.phaseText || 'Starting the first sync.', counts, sync.runningSince ? `running ${duration(sync.runningSince)}` : ''].filter(Boolean).join(' · ') }),
          jsx('div', { className: 'bbx-bar', children: jsx('i', { style: { width: `${Math.max(2, Math.min(100, percent || 0))}%` } }) }),
          jsx('div', { className: 'bbx-small', children: note })
        ]
      }),
      jsxs('div', {
        style: { display: 'flex', flexDirection: 'column', gap: 8 },
        children: [
          jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => setTab('graph'), children: 'Watch the sync' }),
          asObject(r.dashboard).up ? jsx('button', { type: 'button', className: 'bbx-btn', onClick: () => openDashboard(ctx, r.dashboard.url), children: 'Open dashboard' }) : null
        ]
      })
    ]
  })
}

// ---------------------------------------------------------------- the page

function BlackboxPage({ ctx }) {
  const [tab, setTab] = useState('overview')
  const status = useStatus()
  const ready = useReadiness()
  const s = status.data
  const r = asObject(ready.data)
  const setupScreen = r.available === true && SETUP_SCREEN_STAGES.includes(r.stage)
  if (s && !s.available) {
    return jsxs('div', {
      className: 'bbx',
      children: [
        jsx('style', { children: PAGE_CSS }),
        jsx('div', { className: 'bbx-wrap', children: jsxs('div', { children: [jsx('h2', { className: 'bbx-h2', children: 'Blackbox is not running in this Hermes' }), jsx('p', { className: 'bbx-sub', children: 'Enable the blackbox plugin (hermes plugins enable blackbox) and run hermes blackbox setup.' })] }) })
      ]
    })
  }
  return jsxs('div', {
    className: 'bbx',
    children: [
      jsx('style', { children: PAGE_CSS }),
      jsxs('div', {
        className: 'bbx-wrap',
        children: [
          jsxs('div', {
            className: 'bbx-top',
            children: [
              jsxs('div', { className: 'bbx-brand', children: ['BLACKB', jsx('span', { className: 'bbx-brand-dot' }), 'X'] }),
              setupScreen ? null : jsxs('div', {
                className: 'bbx-tabs',
                style: { marginLeft: 12 },
                role: 'tablist',
                children: [['overview', 'Overview'], ['graph', 'Threat graph'], ['shields', 'Shields'], ['settings', 'Settings']].map(([id, label]) =>
                  jsx('button', { type: 'button', role: 'tab', className: 'bbx-tab', 'aria-selected': tab === id ? 'true' : 'false', onClick: () => setTab(id), children: label }, id)
                )
              }),
              jsx('div', { className: 'bbx-spacer' }),
              s ? jsx('button', { type: 'button', className: `bbx-modepill${s.mode === 'block' ? ' block' : ''}`, title: 'Change the mode in Settings', onClick: () => setTab('settings'), children: s.mode === 'block' ? 'Block mode' : 'Audit mode' }) : null,
              s && s.dashboardUrl && !setupScreen ? jsx('button', { type: 'button', className: 'bbx-iconbtn', title: 'Open the dashboard in your browser', onClick: () => openDashboard(ctx, s.dashboardUrl), children: jsx(Codicon, { name: 'link-external' }) }) : null
            ]
          }),
          setupScreen ? jsx(GettingReady, { r }) : null,
          !setupScreen && tab === 'overview' ? (s ? jsx(Overview, { status: s, setTab, readiness: r, ctx }) : jsx('div', { className: 'bbx-empty', children: 'Loading…' })) : null,
          !setupScreen && tab === 'graph' ? jsx(ThreatGraphTab, { readiness: r }) : null,
          !setupScreen && tab === 'shields' ? jsx(ShieldsTab, {}) : null,
          !setupScreen && tab === 'settings' ? jsx(SettingsTab, {}) : null
        ]
      })
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
