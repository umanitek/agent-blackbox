// Agent Blackbox inside Hermes Desktop: a shield in the status bar, a Blackbox page in the sidebar,
// and an alert the moment Blackbox flags or blocks something an agent tried to do.
//
// Data comes from Blackbox's own backend routes (dashboard/plugin_api.py) through ctx.rest, and the
// live alert from the `plugin.blackbox.finding` event Blackbox's hook sends (desktop/__init__.py).
// The alert and the list carry a title, severity, tool and blocked/flagged, never commands or
// evidence. Plain ESM, no build step: Hermes loads this file uncompiled, so UI is written with
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
import { useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const PAGE = '/blackbox'
const POLL_MS = 10000 // the live event refreshes at once; polling covers a dropped connection
const STATUS_KEY = ['blackbox', 'status']
const FINDINGS_KEY = ['blackbox', 'findings']
const AUDIT_NOTICE_KEY = 'auditNoticeShown' // ctx.storage: the one-time "recording, not blocking" notice

let rest = null // ctx.rest, set in register() and cleared on dispose

const fetchStatus = () => (rest ? rest('/status') : Promise.resolve({ available: false }))
const fetchFindings = () => (rest ? rest('/findings') : Promise.resolve({ available: false }))

function useStatus() {
  return useQuery({ queryKey: STATUS_KEY, queryFn: fetchStatus, refetchInterval: POLL_MS })
}

const modeLabel = mode => (mode === 'block' ? 'Block' : 'Audit')

// The Audit / Block switch. Saved by Blackbox's own checked settings path (POST /mode, which Hermes
// answers only for this app's own credential), never by an agent.
async function setMode(mode) {
  if (!rest) return false
  try {
    const result = await rest('/mode', { method: 'POST', body: { mode } })
    queryClient.invalidateQueries({ queryKey: STATUS_KEY })
    if (result && result.ok) {
      host.notify({
        kind: 'success',
        message: mode === 'block' ? 'Blocking is on: Blackbox now stops threats' : 'Audit mode: Blackbox records threats but does not stop them'
      })
      return true
    }
    host.notify({ kind: 'error', message: `Could not change the mode: ${(result && (result.errors || []).join('; ')) || (result && result.error) || 'unknown error'}` })
  } catch (error) {
    host.notifyError(error, 'Could not change the mode')
  }
  return false
}
const severityVariant = severity =>
  severity === 'critical' || severity === 'high' ? 'destructive' : severity === 'medium' ? 'warn' : 'muted'

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

function Fact({ label, value }) {
  return jsxs('div', {
    className: 'flex flex-col gap-0.5',
    children: [
      jsx('span', { className: 'text-[0.65rem] uppercase tracking-wide text-(--ui-text-quaternary)', children: label }),
      jsx('span', { className: 'text-sm text-(--ui-text-secondary)', children: value })
    ]
  })
}

function FindingRow({ item }) {
  return jsxs('div', {
    className: 'flex items-center gap-2 border-b border-(--ui-stroke-secondary) py-2 text-sm',
    children: [
      jsx(Badge, { variant: item.outcome === 'blocked' ? 'destructive' : 'warn', children: item.outcome }),
      jsx(Badge, { variant: severityVariant(item.severity), children: item.severity }),
      jsx('span', { className: 'min-w-0 flex-1 truncate text-(--ui-text-secondary)', children: item.title }),
      item.more > 0 ? jsx(Badge, { variant: 'outline', children: `+${item.more} more` }) : null,
      jsx('span', { className: 'text-[0.7rem] text-(--ui-text-tertiary)', children: item.tool }),
      jsx('span', {
        className: 'w-20 text-right text-[0.7rem] text-(--ui-text-quaternary)',
        children: item.time ? relativeTime(item.time * 1000) : ''
      })
    ]
  })
}

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
        className: 'flex items-center gap-2',
        children: [
          jsx('span', { className: 'text-[0.7rem] uppercase tracking-wide text-(--ui-text-quaternary)', children: 'Mode' }),
          option('audit', 'Audit: record only'),
          option('block', 'Block: stop threats')
        ]
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

function openDashboard(ctx, url) {
  ctx.os.openExternal(url).then(opened => {
    if (!opened) host.notify({ kind: 'warning', message: `Open ${url} in your browser` })
  })
}

function BlackboxPage({ ctx }) {
  const status = useStatus()
  const findings = useQuery({ queryKey: FINDINGS_KEY, queryFn: fetchFindings, refetchInterval: POLL_MS })
  const s = status.data
  const items = (findings.data && findings.data.findings) || []

  if (s && !s.available) {
    return jsxs('div', {
      className: 'flex h-full flex-col gap-2 p-6 text-sm text-(--ui-text-secondary)',
      children: [
        jsx('div', { className: 'font-medium', children: 'Blackbox is not running in this Hermes' }),
        jsx('div', {
          className: 'text-(--ui-text-tertiary)',
          children: 'Enable the blackbox plugin (hermes plugins enable blackbox) and run hermes blackbox setup.'
        })
      ]
    })
  }

  const rules = s && s.rules != null ? s.rules.toLocaleString() : 'loading'
  const synced = s && s.syncedAt ? relativeTime(s.syncedAt * 1000) : 'not yet'

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
            ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => openDashboard(ctx, s.dashboardUrl), children: 'All settings' })
            : null
        ]
      }),
      jsx('p', {
        className: 'max-w-2xl text-sm text-(--ui-text-tertiary)',
        children:
          s && s.mode === 'block'
            ? `Blackbox checks every tool call and model request before it runs, and refuses those at or above ${s.blockSeverity} severity.`
            : 'Blackbox checks every tool call and model request before it runs, and records what it finds. In audit mode it does not stop anything: turn on Block to have it refuse threats.'
      }),
      s ? jsx(ModeSwitch, { mode: s.mode }) : null,
      jsxs('div', {
        className: 'grid grid-cols-2 gap-4 sm:grid-cols-4',
        children: [
          jsx(Fact, { label: 'Threat rules', value: rules }),
          jsx(Fact, { label: 'Last synced', value: synced }),
          jsx(Fact, { label: 'Caught today', value: s ? String(s.today.findings) : '–' }),
          jsx(Fact, { label: 'Blocked today', value: s ? String(s.today.blocked) : '–' })
        ]
      }),
      jsxs('div', {
        className: 'flex flex-col',
        children: [
          jsx('div', { className: 'pb-1 text-[0.7rem] uppercase tracking-wide text-(--ui-text-quaternary)', children: 'Recent findings' }),
          items.length === 0
            ? jsx('div', {
                className: 'py-6 text-sm text-(--ui-text-tertiary)',
                children: 'Nothing flagged yet. Blackbox is watching every tool call your agents make.'
              })
            : items.map((item, index) => jsx(FindingRow, { item }, `${item.time}-${index}`))
        ]
      })
    ]
  })
}

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
      announce(ctx, event && event.payload)
    })
  }
}
