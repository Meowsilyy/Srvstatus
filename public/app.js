const $ = id => document.getElementById(id)
const form = $('lookupForm')
const input = $('targetInput')
const button = $('lookupButton')
const results = $('results')
const emptyState = $('emptyState')
const loadingState = $('loadingState')
const errorBox = $('errorBox')
const runState = $('runState')
const runTime = $('runTime')
const loadingElapsed = $('loadingElapsed')
const settingsPanel = $('settingsPanel')
const settingsBackdrop = $('settingsBackdrop')
let currentData = null
let timer = null
const defaults = {
  theme: 'dark',
  compact: false,
  scanMode: 'common',
  scanTimeout: 500,
  showClosed: false,
  minecraft: true,
  restoreLast: false,
  recent: true
}
let settings = loadSettings()

function loadSettings() {
  try {
    const raw = localStorage.getItem('serverstatus-settings') || localStorage.getItem('serverinfo-settings') || '{}'
    return { ...defaults, ...JSON.parse(raw) }
  } catch {
    return { ...defaults }
  }
}

function saveSettings() {
  localStorage.setItem('serverstatus-settings', JSON.stringify(settings))
}

function resolveTheme(choice) {
  if (choice === 'system') return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  return choice === 'light' ? 'light' : 'dark'
}

function applyTheme() {
  const resolved = resolveTheme(settings.theme)
  document.documentElement.dataset.theme = resolved
  document.documentElement.dataset.themeChoice = settings.theme
  document.documentElement.dataset.compact = settings.compact ? 'true' : 'false'
  document.querySelector('meta[name="theme-color"]').setAttribute('content', resolved === 'light' ? '#f1f2f0' : '#090a0c')
}

function syncSettingsUi() {
  $('settingTheme').value = settings.theme
  $('settingCompact').checked = settings.compact
  $('settingScanMode').value = settings.scanMode
  $('settingScanTimeout').value = String(settings.scanTimeout)
  $('settingShowClosed').checked = settings.showClosed
  $('settingMinecraft').checked = settings.minecraft
  $('settingRestoreLast').checked = settings.restoreLast
  $('settingRecent').checked = settings.recent
  applyTheme()
  renderRecentTargets()
}

function openSettings() {
  settingsPanel.classList.add('open')
  settingsPanel.setAttribute('aria-hidden', 'false')
  settingsBackdrop.classList.remove('hidden')
}

function closeSettings() {
  settingsPanel.classList.remove('open')
  settingsPanel.setAttribute('aria-hidden', 'true')
  settingsBackdrop.classList.add('hidden')
}

$('settingsButton').addEventListener('click', openSettings)
$('settingsClose').addEventListener('click', closeSettings)
settingsBackdrop.addEventListener('click', closeSettings)
window.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeSettings()
})
$('settingTheme').addEventListener('change', event => {
  settings.theme = event.target.value
  saveSettings()
  applyTheme()
})
$('settingCompact').addEventListener('change', event => {
  settings.compact = event.target.checked
  saveSettings()
  applyTheme()
})
$('settingScanMode').addEventListener('change', event => {
  settings.scanMode = event.target.value
  saveSettings()
})
$('settingScanTimeout').addEventListener('change', event => {
  settings.scanTimeout = Number(event.target.value)
  saveSettings()
})
$('settingShowClosed').addEventListener('change', event => {
  settings.showClosed = event.target.checked
  saveSettings()
  if (currentData) renderServices(currentData)
})
$('settingMinecraft').addEventListener('change', event => {
  settings.minecraft = event.target.checked
  saveSettings()
})
$('settingRestoreLast').addEventListener('change', event => {
  settings.restoreLast = event.target.checked
  saveSettings()
})
$('settingRecent').addEventListener('change', event => {
  settings.recent = event.target.checked
  saveSettings()
  renderRecentTargets()
})
$('settingsClearRecent').addEventListener('click', () => {
  localStorage.removeItem('serverstatus-recent-targets')
  localStorage.removeItem('serverinfo-recent-targets')
  renderRecentTargets()
})
$('settingsReset').addEventListener('click', () => {
  settings = { ...defaults }
  saveSettings()
  syncSettingsUi()
})
matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
  if (settings.theme === 'system') applyTheme()
})

function getRecentTargets() {
  if (!settings.recent) return []
  try {
    const raw = localStorage.getItem('serverstatus-recent-targets') || localStorage.getItem('serverinfo-recent-targets') || '[]'
    const values = JSON.parse(raw)
    return Array.isArray(values) ? values.filter(Boolean).slice(0, 6) : []
  } catch {
    return []
  }
}

function rememberTarget(target) {
  if (!settings.recent) return
  const values = [target, ...getRecentTargets().filter(value => value.toLowerCase() !== target.toLowerCase())].slice(0, 6)
  localStorage.setItem('serverstatus-recent-targets', JSON.stringify(values))
  renderRecentTargets()
}

function renderRecentTargets() {
  const bar = $('recentBar')
  const host = $('recentTargets')
  if (!bar || !host) return
  const values = getRecentTargets()
  if (!values.length) {
    bar.classList.add('hidden')
    host.innerHTML = ''
    return
  }
  bar.classList.remove('hidden')
  host.innerHTML = values.map(value => `<button class="recenttarget" type="button" data-target="${escapeHtml(value)}">${escapeHtml(value)}</button>`).join('')
  host.querySelectorAll('.recenttarget').forEach(item => item.addEventListener('click', () => {
    input.value = item.dataset.target
    performLookup(item.dataset.target)
  }))
}

const escapeHtml = value => String(value ?? '')
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;')

syncSettingsUi()

function display(value) {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'boolean') return value ? 'YES' : 'NO'
  if (Array.isArray(value)) return value.length ? value.map(v => typeof v === 'object' ? JSON.stringify(v) : String(v)).join(', ') : '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function short(value, max = 120) {
  const text = display(value)
  return text.length > max ? `${text.slice(0, max)}…` : text
}

function tag(text, type = '') {
  return `<span class="tag ${type}">${escapeHtml(text)}</span>`
}

function metric(label, value, note = '') {
  return `<div class="metric"><label>${escapeHtml(label)}</label><strong>${escapeHtml(display(value))}</strong>${note ? `<small>${escapeHtml(note)}</small>` : ''}</div>`
}

function kv(rows) {
  return `<div class="kv">${rows.map(([k, v, cls = '']) => `<div class="k">${escapeHtml(k)}</div><div class="v ${cls}">${escapeHtml(display(v))}</div>`).join('')}</div>`
}

function block(title, html) {
  return `<div class="block"><h3>${escapeHtml(title)}</h3>${html}</div>`
}

function table(headers, rows) {
  if (!rows?.length) return '<div class="notice">No data returned.</div>'
  return `<div class="tablewrap"><table><thead><tr>${headers.map(h => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(cell => `<td>${escapeHtml(display(cell))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
}

function objectRows(obj) {
  if (!obj) return []
  return Object.entries(obj).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : v])
}

function formatDate(value) {
  if (!value) return '—'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString()
}

function protocolColor(value) {
  if (!value) return ''
  return /TLSv1\.3|h2|HTTP\/2|HTTP\/3/i.test(value) ? 'good' : ''
}

function renderOverview(data) {
  const s = data.summary || {}
  $('generatedAt').textContent = `${data.meta.durationMs} ms · ${new Date(data.meta.generatedAt).toLocaleTimeString()}`
  $('overviewGrid').innerHTML = [
    metric('Target', s.target),
    metric('HTTP', s.httpStatus || (s.online ? 'Reachable' : 'No response')),
    metric('Primary IP', s.primaryIp),
    metric('Provider', s.networkProvider || s.networkOwner || '—'),
    metric('Edge / CDN', s.edgeProvider || '—', s.edgePoint ? `POP ${s.edgePoint}` : ''),
    metric('Server software', s.server || '—'),
    metric('Open services', s.openPortCount != null ? s.openPortCount : '—'),
    metric('ASN', s.asn || '—'),
    metric('Location', [s.region, s.country].filter(Boolean).join(', ') || '—'),
    metric('TLS', s.tlsVersion || '—'),
    metric('HTTP version', s.httpVersion || '—'),
    metric('DNS provider', s.dnsProvider || '—'),
    metric('Mail provider', s.mailProvider || '—'),
    metric('Registrar', s.registrar || '—'),
    metric('Domain age', s.domainAgeYears != null ? `${s.domainAgeYears} years` : '—'),
    metric('IPv6', s.ipv6Supported ? `Yes · ${s.ipv6Count}` : 'No'),
    metric('Runtime', s.poweredBy || '—')
  ].join('')
  const signals = []
  signals.push(tag(s.online ? 'HTTP reachable' : 'HTTP no response', s.online ? 'good' : 'bad'))
  if (s.networkProvider) signals.push(tag(s.networkProvider, 'info'))
  if (s.openPortCount != null) signals.push(tag(`${s.openPortCount} open service${s.openPortCount === 1 ? '' : 's'}`, s.openPortCount ? 'warn' : 'good'))
  if (s.edgeProvider) signals.push(tag(`${s.edgeProvider}${s.edgePoint ? ` · ${s.edgePoint}` : ''}`, 'info'))
  if (s.dnssec === true) signals.push(tag('DNSSEC validated', 'good'))
  if (s.minecraftJavaOnline) signals.push(tag('Minecraft Java online', 'good'))
  if (s.minecraftBedrockOnline) signals.push(tag('Minecraft Bedrock online', 'good'))
  if (data.web?.page?.http3Advertised) signals.push(tag('HTTP/3 advertised', 'good'))
  if (data.tls?.certificate?.validTo) {
    const days = Math.floor((new Date(data.tls.certificate.validTo) - Date.now()) / 86400000)
    signals.push(tag(`Certificate ${days}d`, days < 14 ? 'bad' : days < 30 ? 'warn' : 'good'))
  }
  $('overviewSignals').innerHTML = signals.join('')
}

function renderInfrastructure(data) {
  const i = data.infrastructure || {}
  const provider = kv([
    ['Observed provider', i.observedProvider],
    ['Network owner', i.networkOwner],
    ['ISP', i.isp],
    ['ASN', i.asn],
    ['Network domain', i.networkDomain],
    ['Reverse DNS', i.reverseDns]
  ])
  const services = kv([
    ['DNS provider', i.dnsProvider],
    ['Mail provider', i.mailProvider],
    ['Edge / CDN', i.edgeProvider],
    ['Edge point', i.edgePoint],
    ['Resolved addresses', i.resolvedAddressCount]
  ])
  const software = kv([
    ['Server', i.serverSoftware],
    ['Powered by', i.poweredBy],
    ['Via', i.via],
    ['HTTP stack', data.web?.httpVersion],
    ['TLS', data.tls?.protocol],
    ['ALPN', data.tls?.alpn || data.web?.alpnProtocol]
  ])
  const evidence = i.providerEvidence?.length ? `<div class="evidence">${i.providerEvidence.map(x => tag(x, 'info')).join('')}</div>` : ''
  $('infrastructureBody').innerHTML = `<div class="grid3">${block('Provider', provider)}${block('Services', services)}${block('Server stack', software)}</div>${evidence}`
}

function renderServices(data) {
  const scan = data.serviceScan || {}
  if (scan.mode === 'off') {
    $('servicesBody').innerHTML = '<div class="notice">Service scan is off.</div>'
    return
  }
  if (!scan.results?.length) {
    $('servicesBody').innerHTML = '<div class="notice">No service scan results were returned.</div>'
    return
  }
  const open = scan.results.filter(item => item.open)
  const summary = kv([
    ['Address', scan.address],
    ['Mode', scan.mode],
    ['Ports checked', scan.checked],
    ['Open', open.length],
    ['Timeout', `${scan.timeoutMs} ms`],
    ['Duration', `${scan.durationMs} ms`]
  ])
  const rows = scan.results.map(item => [item.port, item.service, item.open ? 'OPEN' : 'closed', item.open && item.latencyMs != null ? `${item.latencyMs} ms` : '—'])
  const openTable = block('Open services', table(['port', 'service', 'state', 'latency'], rows.filter(row => row[2] === 'OPEN')))
  const checked = settings.showClosed ? block('Checked ports', table(['port', 'service', 'state', 'latency'], rows)) : ''
  $('servicesBody').innerHTML = `<div class="grid2">${block('Scan', summary)}${openTable}</div>${checked}`
}

function renderHttp(data) {
  const w = data.web
  if (!w) {
    $('httpBody').innerHTML = '<div class="notice">No HTTP response.</div>'
    return
  }
  const page = w.page || {}
  const left = kv([
    ['Final URL', w.finalUrl],
    ['Status', `${w.status} ${w.statusMessage || ''}`.trim()],
    ['HTTP version', w.httpVersion, protocolColor(w.httpVersion)],
    ['Remote socket', `${w.remoteAddress || '—'}:${w.remotePort || '—'}`],
    ['ALPN', w.alpnProtocol || '—', protocolColor(w.alpnProtocol)],
    ['TLS protocol', w.tlsProtocol || '—', protocolColor(w.tlsProtocol)],
    ['TTFB', w.timings?.ttfbMs != null ? `${w.timings.ttfbMs} ms` : '—'],
    ['Total', w.timings?.totalMs != null ? `${w.timings.totalMs} ms` : '—']
  ])
  const right = kv([
    ['Title', page.title],
    ['Description', page.description],
    ['Language', page.language],
    ['Charset', page.charset],
    ['Content-Type', page.contentType],
    ['Sampled body', `${page.bytesSampled ?? 0} bytes`],
    ['Compression', page.compression],
    ['HTTP/3 advertised', page.http3Advertised]
  ])
  const redirects = table(['status', 'url', 'location', 'ttfb'], (w.redirects || []).map(r => [r.status, r.url, r.location, `${r.ttfbMs} ms`]))
  const cache = kv([
    ['Cache-Control', page.cacheControl],
    ['Age', page.age],
    ['ETag', page.etag],
    ['Last-Modified', page.lastModified],
    ['Server-Timing', page.serverTiming],
    ['Server clock skew', page.clockSkewSeconds == null ? '—' : `${page.clockSkewSeconds}s`],
    ['Body sample SHA-256', page.sampleSha256],
    ['Headers SHA-256', page.headersSha256]
  ])
  const headers = table(['header', 'value'], Object.entries(w.headers || {}).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, Array.isArray(v) ? v.join(' | ') : v]))
  $('httpBody').innerHTML = `<div class="grid2">${block('Response', left)}${block('Page', right)}</div>${block('Redirect chain', redirects)}<div class="grid2">${block('Cache / timing', cache)}${block('Response headers', headers)}</div>`
}

function renderEdge(data) {
  const e = data.edge || {}
  const summary = kv([
    ['Provider', e.provider || 'Not identified'],
    ['Edge detected', e.detected],
    ['Cloudflare', e.cloudflare || 'unknown', e.cloudflare === 'detected' ? 'good' : ''],
    ['POP / edge point', e.edgePoint],
    ['Path', e.requestPath]
  ])
  const evidence = e.evidence?.length ? `<div class="evidence">${e.evidence.map(x => tag(x, 'info')).join('')}</div>` : '<div class="notice">No clear CDN or proxy fingerprint.</div>'
  $('edgeBody').innerHTML = `${summary}${evidence}`
}

function renderNetwork(data) {
  const n = data.network || {}
  const geo = n.geolocation || {}
  const conn = geo.connection || {}
  const reg = n.registration || {}
  const addresses = table(['address', 'family'], (n.resolvedAddresses || []).map(a => [a.address, `IPv${a.family}`]))
  const geoKv = kv([
    ['IP', geo.ip],
    ['Country', geo.country ? `${geo.country} (${geo.countryCode || ''})` : null],
    ['Region', geo.region],
    ['City', geo.city],
    ['Coordinates', geo.latitude != null ? `${geo.latitude}, ${geo.longitude}` : null],
    ['Timezone', geo.timezone?.id || geo.timezone],
    ['ASN', conn.asn],
    ['ISP', conn.isp],
    ['Organization', conn.org],
    ['Network domain', conn.domain]
  ])
  const regKv = kv([
    ['Network name', reg.name],
    ['Handle', reg.handle],
    ['Type', reg.type],
    ['Range', reg.startAddress && reg.endAddress ? `${reg.startAddress} → ${reg.endAddress}` : null],
    ['IP version', reg.ipVersion],
    ['Registry country', reg.country],
    ['Parent handle', reg.parentHandle],
    ['Status', reg.status]
  ])
  const entities = table(['entity', 'roles'], (reg.entities || []).map(e => [e.name, e.roles?.join(', ')]))
  $('networkBody').innerHTML = `<div class="grid3">${block('Addresses', addresses)}${block('Location / ASN', geoKv)}${block('IP registration', regKv)}</div>${block('Network entities', entities)}`
}

function renderDns(data) {
  const d = data.dns || {}
  const dnssec = data.dnssec || {}
  const basic = []
  for (const value of d.a || []) basic.push(['A', value, ''])
  for (const value of d.aaaa || []) basic.push(['AAAA', value, ''])
  for (const value of d.cname || []) basic.push(['CNAME', value, ''])
  for (const value of d.ns || []) basic.push(['NS', value, ''])
  for (const value of d.ptr || []) basic.push(['PTR', value, ''])
  for (const value of d.mx || []) basic.push(['MX', value.exchange, `priority ${value.priority}`])
  for (const value of d.caa || []) basic.push(['CAA', value.value, `critical ${value.critical}`])
  const records = table(['type', 'value', 'meta'], basic)
  const txt = table(['TXT'], (d.txt || []).map(x => [x]))
  const services = []
  for (const [name, rows] of Object.entries(d.services || {})) for (const row of rows) services.push([name, row.name, row.port, row.priority, row.weight])
  const srv = table(['service', 'target', 'port', 'priority', 'weight'], services)
  const dnssecKv = kv([
    ['Validated', dnssec.authenticatedData],
    ['DNS status', dnssec.status],
    ['Checking disabled', dnssec.checkingDisabled],
    ['Truncated', dnssec.truncated],
    ['Resolver comment', dnssec.comment]
  ])
  const soa = kv(objectRows(d.soa))
  $('dnsBody').innerHTML = `${block('Address / routing records', records)}<div class="grid2">${block('TXT', txt)}${block('DNSSEC', dnssecKv)}</div><div class="grid2">${block('SRV services', srv)}${block('SOA', soa)}</div>`
}

function renderTls(data) {
  const t = data.tls || {}
  if (!t.available) {
    $('tlsBody').innerHTML = `<div class="notice">TLS details unavailable: ${escapeHtml(t.reason || 'No TLS response')}</div>`
    return
  }
  const c = t.certificate || {}
  const certDays = c.validTo ? Math.floor((new Date(c.validTo) - Date.now()) / 86400000) : null
  const negotiated = kv([
    ['Protocol', t.protocol, protocolColor(t.protocol)],
    ['ALPN', t.alpn, protocolColor(t.alpn)],
    ['Cipher', t.cipher?.name],
    ['Cipher version', t.cipher?.version],
    ['Cipher bits', t.cipher?.bits],
    ['Ephemeral key', t.ephemeralKey?.type ? `${t.ephemeralKey.type} ${t.ephemeralKey.size || ''}` : null],
    ['Certificate authorized', t.authorized, t.authorized ? 'good' : 'warn'],
    ['Authorization error', t.authorizationError],
    ['OCSP stapled', t.ocspStapled]
  ])
  const cert = kv([
    ['Subject', c.subject ? JSON.stringify(c.subject) : null],
    ['Issuer', c.issuer ? JSON.stringify(c.issuer) : null],
    ['SAN', c.subjectAltName],
    ['Valid from', formatDate(c.validFrom)],
    ['Valid to', formatDate(c.validTo)],
    ['Days remaining', certDays],
    ['Serial', c.serialNumber],
    ['SHA-256 fingerprint', c.fingerprint256],
    ['Fingerprint', c.fingerprint],
    ['Key bits', c.bits || c.pubkeyBits]
  ])
  $('tlsBody').innerHTML = `<div class="grid2">${block('Negotiation', negotiated)}${block('Certificate', cert)}</div>`
}

function renderSecurity(data) {
  const s = data.security
  if (!s) {
    $('securityBody').innerHTML = '<div class="notice">Security header analysis requires an HTTP response.</div>'
    return
  }
  const gradeType = s.score >= 80 ? 'good' : s.score >= 60 ? 'warn' : 'bad'
  const checks = `<div class="checklist">${(s.checks || []).map(c => `<div class="check ${c.pass ? 'pass' : 'fail'}"><span>${escapeHtml(c.name)}</span><span>${c.pass ? `PASS +${c.weight}` : 'MISSING'}</span></div>`).join('')}</div>`
  const details = kv(objectRows(s.details).map(([k, v]) => [k, v]))
  $('securityBody').innerHTML = `<div class="notice"><strong class="${gradeType}">${escapeHtml(s.grade)} · ${escapeHtml(s.score)}/100</strong> &nbsp; ${escapeHtml(s.note)}</div>${checks}${block('Header detail', details)}`
}

function renderRegistration(data) {
  const r = data.registration
  if (!r) {
    $('registrationBody').innerHTML = '<div class="notice">No RDAP domain record.</div>'
    return
  }
  const basics = kv([
    ['Domain', r.ldhName],
    ['Unicode name', r.unicodeName],
    ['Handle', r.handle],
    ['Registrar', r.registrar],
    ['Status', r.status],
    ['Age', r.domainAge ? `${r.domainAge.years} years · ${r.domainAge.days} days` : null],
    ['Registration', formatDate(r.events?.registration)],
    ['Expiration', formatDate(r.events?.expiration)],
    ['Last changed', formatDate(r.events?.['last changed'])],
    ['DNSSEC delegation signed', r.secureDns?.delegationSigned]
  ])
  const nameservers = table(['nameserver'], (r.nameservers || []).map(n => [n]))
  const events = table(['event', 'date'], Object.entries(r.events || {}).map(([k, v]) => [k, formatDate(v)]))
  $('registrationBody').innerHTML = `${block('Domain record', basics)}<div class="grid2">${block('Nameservers', nameservers)}${block('Events', events)}</div>`
}

function renderEmail(data) {
  const e = data.email
  if (!e) {
    $('emailBody').innerHTML = '<div class="notice">No mail DNS data for this target.</div>'
    return
  }
  const mx = table(['priority', 'exchange'], (e.mx || []).map(x => [x.priority, x.exchange]))
  const auth = table(['record', 'value'], [
    ...(e.spf || []).map(v => ['SPF', v]),
    ...(e.dmarc || []).map(v => ['DMARC', v]),
    ...(e.mtaSts || []).map(v => ['MTA-STS', v]),
    ...(e.bimi || []).map(v => ['BIMI', v])
  ])
  $('emailBody').innerHTML = `<div class="grid2">${block('MX', mx)}${block('Authentication / policy', auth)}</div>`
}

function renderTechnology(data) {
  const rows = (data.technologies || []).map(t => [t.name, t.category || '—', t.confidence, t.evidence])
  $('technologyBody').innerHTML = table(['technology', 'type', 'confidence', 'evidence'], rows)
}

function minecraftPanel(label, mc) {
  if (!mc) return block(label, '<div class="notice">No Minecraft status response.</div>')
  const online = mc.online === true
  const motd = mc.motd?.clean || mc.motd?.raw || []
  const plugins = mc.plugins || []
  const mods = mc.mods || []
  const players = mc.players?.list || []
  const status = kv([
    ['Online', online, online ? 'good' : 'bad'],
    ['IP', mc.ip],
    ['Port', mc.port],
    ['Hostname', mc.hostname],
    ['Version', mc.version],
    ['Protocol', mc.protocol ? JSON.stringify(mc.protocol) : null],
    ['Players', mc.players ? `${mc.players.online}/${mc.players.max}` : null],
    ['MOTD', Array.isArray(motd) ? motd.join(' / ') : motd],
    ['Map', mc.map ? JSON.stringify(mc.map) : null],
    ['Software', mc.software],
    ['EULA blocked', mc.eula_blocked],
    ['Debug', mc.debug ? JSON.stringify(mc.debug) : null]
  ])
  const extra = `${plugins.length ? `<h3>Plugins</h3>${table(['name', 'version'], plugins.map(p => [p.name, p.version]))}` : ''}${mods.length ? `<h3>Mods</h3>${table(['name', 'version'], mods.map(p => [p.name, p.version]))}` : ''}${players.length ? `<h3>Visible players</h3>${table(['name', 'uuid'], players.map(p => [p.name, p.uuid]))}` : ''}`
  const icon = mc.icon ? `<div class="notice"><img src="${escapeHtml(mc.icon)}" width="48" height="48" alt="Server icon" style="vertical-align:middle;margin-right:12px;image-rendering:pixelated"><span>Server icon returned by status ping</span></div>` : ''
  return block(label, `${icon}${status}${extra}`)
}

function renderMinecraft(data) {
  const m = data.minecraft || {}
  if (m.skipped) {
    $('minecraftBody').innerHTML = '<div class="notice">Minecraft lookup is off.</div>'
    return
  }
  $('minecraftBody').innerHTML = `<div class="notice"><strong>${escapeHtml(m.address || '')}</strong> · ${escapeHtml(m.cacheNote || '')}</div><div class="grid2">${minecraftPanel('Java', m.java)}${minecraftPanel('Bedrock', m.bedrock)}</div>`
}

function resourceBlock(name, item) {
  if (!item) return block(name, '<div class="notice">Unavailable.</div>')
  const info = kv([
    ['URL', item.url],
    ['Status', item.status],
    ['Content-Type', item.contentType],
    ['Bytes sampled', item.bytesRead]
  ])
  const preview = item.preview ? `<pre class="resourcepre">${escapeHtml(item.preview)}</pre>` : ''
  return block(name, info + preview)
}

function renderFiles(data) {
  const r = data.resources || {}
  $('filesBody').innerHTML = `<div class="grid2">${resourceBlock('robots.txt', r.robots)}${resourceBlock('sitemap.xml', r.sitemap)}${resourceBlock('security.txt', r.securityTxt)}${resourceBlock('favicon.ico', r.favicon)}</div>`
}

function renderAll(data) {
  currentData = data
  renderOverview(data)
  renderInfrastructure(data)
  renderServices(data)
  renderHttp(data)
  renderEdge(data)
  renderNetwork(data)
  renderDns(data)
  renderTls(data)
  renderSecurity(data)
  renderRegistration(data)
  renderEmail(data)
  renderTechnology(data)
  renderMinecraft(data)
  renderFiles(data)
  $('rawJson').textContent = JSON.stringify(data, null, 2)
}

async function performLookup(target) {
  errorBox.classList.add('hidden')
  emptyState.classList.add('hidden')
  results.classList.add('hidden')
  loadingState.classList.remove('hidden')
  button.disabled = true
  runState.textContent = 'Running'
  $('loadingTarget').textContent = target
  const started = performance.now()
  clearInterval(timer)
  timer = setInterval(() => {
    const sec = (performance.now() - started) / 1000
    loadingElapsed.textContent = `${sec.toFixed(1)}s`
    runTime.textContent = `${sec.toFixed(1)}s`
  }, 100)
  try {
    const response = await fetch('/api/lookup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target,
        options: {
          scanMode: settings.scanMode,
          scanTimeout: settings.scanTimeout,
          minecraft: settings.minecraft
        }
      })
    })
    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'Lookup failed')
    renderAll(data)
    loadingState.classList.add('hidden')
    results.classList.remove('hidden')
    runState.textContent = 'Done'
    runTime.textContent = `${data.meta.durationMs}ms`
    const url = new URL(location.href)
    url.searchParams.set('q', target)
    history.replaceState(null, '', url)
    localStorage.setItem('serverstatus-last-target', target)
    rememberTarget(target)
  } catch (error) {
    loadingState.classList.add('hidden')
    errorBox.textContent = error.message
    errorBox.classList.remove('hidden')
    runState.textContent = 'Error'
    runTime.textContent = '—'
  } finally {
    clearInterval(timer)
    button.disabled = false
  }
}

form.addEventListener('submit', event => {
  event.preventDefault()
  const target = input.value.trim()
  if (target) performLookup(target)
})

$('copyJson').addEventListener('click', async () => {
  if (!currentData) return
  await navigator.clipboard.writeText(JSON.stringify(currentData, null, 2))
  $('copyJson').textContent = 'Copied'
  setTimeout(() => $('copyJson').textContent = 'Copy', 900)
})

const observer = new IntersectionObserver(entries => {
  const visible = entries.filter(e => e.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]
  if (!visible) return
  document.querySelectorAll('.rail a').forEach(a => a.classList.toggle('active', a.getAttribute('href') === `#${visible.target.id}`))
}, { rootMargin: '-70px 0px -70% 0px', threshold: [0, .2, .5] })

document.querySelectorAll('.section').forEach(section => observer.observe(section))

const queryTarget = new URL(location.href).searchParams.get('q')
const restoredTarget = settings.restoreLast ? (localStorage.getItem('serverstatus-last-target') || localStorage.getItem('serverinfo-last-target')) : null
const initial = queryTarget || restoredTarget
if (initial) {
  input.value = initial
  performLookup(initial)
}
