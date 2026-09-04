const $ = id => document.getElementById(id)
let kind = 'website'
let report = null
let section = 'overview'

const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))
const arr = value => Array.isArray(value) ? value : []
const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {}
const fmt = value => value === null || value === undefined || value === '' ? '—' : String(value)

function toast(text){const el=$('toast');el.textContent=text;el.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(()=>el.classList.remove('show'),1500)}
async function copy(value){try{await navigator.clipboard.writeText(String(value));toast('Copied')}catch{toast('Copy failed')}}
function copyBtn(value){if(value===null||value===undefined||value==='')return'';return `<button class="copy" data-copy="${esc(String(value))}" title="Copy">⧉</button>`}
function row(key,value,mono=false,copyable=false){return `<div class="row"><div class="row-key">${esc(key)}</div><div class="row-value ${mono?'mono':''}">${esc(fmt(value))}${copyable?copyBtn(value):''}</div></div>`}
function tags(values,cls=''){const clean=arr(values).filter(Boolean);return clean.length?clean.map(v=>`<span class="tag ${cls}">${esc(typeof v==='string'?v:JSON.stringify(v))}</span>`).join(''):'<span class="muted-inline">None</span>'}
function head(title,sub='',actions=''){return `<div class="section-head"><div><h2>${esc(title)}</h2>${sub?`<p>${esc(sub)}</p>`:''}</div><div class="actions">${actions}</div></div>`}
function triggerDownload(blob,filename){const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=filename;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function saveText(name,text,type='text/plain'){triggerDownload(new Blob([text],{type}),name)}
function filenameFromResponse(res,fallback){const cd=res.headers.get('content-disposition')||'';const m=cd.match(/filename="?([^";]+)"?/i);return m?m[1]:fallback}

function setKind(next){
  kind=next
  report=null
  section=next==='minecraft'?'minecraft':next==='pack'?'pack':'overview'
  document.querySelectorAll('.kind').forEach(b=>b.classList.toggle('active',b.dataset.kind===next))
  $('profileSelect').classList.toggle('hidden',next!=='website')
  $('valueInput').placeholder=next==='minecraft'?'play.example.net:25565':next==='pack'?'https://cdn.example.net/resource-pack.zip':'https://example.com'
  $('hint').textContent=next==='minecraft'?'Java or Bedrock server address.':next==='pack'?'Paste a public resource-pack ZIP URL.':'Public HTTP/HTTPS pages only.'
  $('runBtn').textContent=next==='pack'?'Inspect':next==='minecraft'?'Check':'Unpack'
  $('workspace').classList.add('hidden')
  $('empty').classList.remove('hidden')
  $('empty').innerHTML='<div class="empty-title">Paste an address above.</div>'
  $('status').textContent=''
}

document.querySelectorAll('.kind').forEach(b=>b.addEventListener('click',()=>setKind(b.dataset.kind)))
$('themeBtn').addEventListener('click',()=>{const root=document.documentElement;const next=root.dataset.theme==='light'?'dark':'light';root.dataset.theme=next;localStorage.setItem('unpack-theme',next)})
const savedTheme=localStorage.getItem('unpack-theme');if(savedTheme)document.documentElement.dataset.theme=savedTheme

$('lookupForm').addEventListener('submit',async e=>{
  e.preventDefault()
  const value=$('valueInput').value.trim()
  if(!value)return
  const btn=$('runBtn')
  btn.disabled=true
  $('status').textContent='Loading'
  const started=performance.now()
  try{
    const res=await fetch('/api/unpack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind,value,profile:$('profileSelect').value})})
    const text=await res.text()
    let data
    try{data=JSON.parse(text)}catch{throw new Error(res.ok?'Bad response from server':`HTTP ${res.status}`)}
    if(!res.ok)throw new Error(data.error||`HTTP ${res.status}`)
    report=data
    section=kind==='minecraft'?'minecraft':kind==='pack'?'pack':'overview'
    showWorkspace()
    render()
    $('status').textContent=`${Math.round(performance.now()-started)} ms${data.meta?.cached?' · cached':''}`
  }catch(err){
    report=null
    $('workspace').classList.add('hidden')
    $('empty').classList.remove('hidden')
    $('empty').innerHTML=`<div class="empty-title">Didn't load.</div><div class="empty-copy">${esc(err.message||'Request failed')}</div>`
    $('status').textContent='Failed'
  }finally{btn.disabled=false}
})

function showWorkspace(){
  $('empty').classList.add('hidden')
  $('workspace').classList.remove('hidden')
  document.querySelectorAll('.web-only').forEach(el=>el.classList.toggle('hidden',kind!=='website'))
  document.querySelectorAll('.mc-only').forEach(el=>el.classList.toggle('hidden',kind!=='minecraft'))
  document.querySelectorAll('.pack-only').forEach(el=>el.classList.toggle('hidden',kind!=='pack'))
}

document.querySelectorAll('.rail-item').forEach(b=>b.addEventListener('click',()=>{section=b.dataset.section;render()}))

document.addEventListener('click',async e=>{
  const copyEl=e.target.closest('[data-copy]');if(copyEl)return copy(copyEl.dataset.copy)
  if(e.target.closest('[data-download-source]')&&report?.source)return saveText('source.html',report.source,'text/html')
  if(e.target.closest('[data-download-json]')&&report)return saveText('unpack-report.json',JSON.stringify(report,null,2),'application/json')
  if(e.target.closest('[data-export-site]'))return exportSite()
  const packDl=e.target.closest('[data-pack-download]');if(packDl)return downloadPack(packDl.dataset.packDownload)
  const packInspect=e.target.closest('[data-pack-inspect]');if(packInspect){setKind('pack');$('valueInput').value=packInspect.dataset.packInspect;$('lookupForm').requestSubmit();return}
  if(e.target.closest('[data-open-pack]')){setKind('pack');$('valueInput').focus()}
})

async function exportSite(){
  const value=report?.overview?.requested||$('valueInput').value.trim()
  if(!value)return
  $('status').textContent='Building ZIP'
  try{
    const res=await fetch('/api/unpack/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value,profile:$('profileSelect').value})})
    if(!res.ok){let msg=`HTTP ${res.status}`;try{const data=await res.json();msg=data.error||msg}catch{}throw new Error(msg)}
    const blob=await res.blob()
    triggerDownload(blob,filenameFromResponse(res,'site-source.zip'))
    $('status').textContent=`ZIP · ${(blob.size/1024/1024).toFixed(1)} MB`
  }catch(err){$('status').textContent='Export failed';toast(err.message||'Export failed')}
}

async function downloadPack(url){
  $('status').textContent='Downloading pack'
  try{
    const res=await fetch('/api/unpack/pack-download',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})})
    if(!res.ok){let msg=`HTTP ${res.status}`;try{const data=await res.json();msg=data.error||msg}catch{}throw new Error(msg)}
    const blob=await res.blob()
    triggerDownload(blob,filenameFromResponse(res,'resource-pack.zip'))
    $('status').textContent=`Pack · ${(blob.size/1024/1024).toFixed(1)} MB`
  }catch(err){$('status').textContent='Pack failed';toast(err.message||'Pack failed')}
}

function render(){
  if(!report)return
  document.querySelectorAll('.rail-item').forEach(b=>b.classList.toggle('active',b.dataset.section===section))
  const fn={overview:renderOverview,source:renderSource,files:renderFiles,network:renderNetwork,headers:renderHeaders,security:renderSecurity,minecraft:renderMinecraft,pack:renderPack,raw:renderRaw}[section]||renderOverview
  $('content').innerHTML=fn()
}

function renderOverview(){
  if(kind==='minecraft')return renderMinecraft()
  if(kind==='pack')return renderPack()
  const o=obj(report.overview),n=obj(report.network),p=obj(report.page),edge=obj(n.edge)
  return head('Overview',o.finalUrl||'',`<button class="small-btn primary-lite" data-export-site>Download ZIP</button><button class="small-btn" data-download-json>JSON</button>`)+`${edge.proxied?`<div class="notice warn">${esc(edge.note||'Public edge detected.')}</div>`:''}<div class="grid"><div class="card two"><div class="label">Page</div><div class="value big">${esc(o.title||hostOf(o.finalUrl)||'Untitled')}</div><div class="value soft-copy">${esc(o.description||'')}</div></div><div class="card"><div class="label">HTTP</div><div class="value big">${esc(o.status)} ${esc(o.statusText||'')}</div></div><div class="card"><div class="label">IP</div><div class="value mono">${esc(n.address)}${copyBtn(n.address)}</div></div><div class="card"><div class="label">Port</div><div class="value mono">${esc(n.port)}${copyBtn(n.port)}</div></div><div class="card"><div class="label">Time</div><div class="value">${esc(o.durationMs)} ms</div></div><div class="card wide"><div class="label">Detected</div>${tags(arr(report.technologies).map(x=>x.name))}</div><div class="card wide">${row('Final URL',o.finalUrl,true,true)}${row('Type',o.contentType)}${row('HTML bytes',o.bytesRead)}${row('SHA-256',o.sourceSha256,true,true)}${row('Links',`${p.links?.internal||0} internal · ${p.links?.external||0} external`)}</div></div>`
}

function renderSource(){
  const note=report.sourceTruncated?'<div class="notice warn">Source preview was cut at the viewer limit. ZIP export still collects linked assets separately.</div>':''
  return head('Source',report.overview?.finalUrl||'',`<button class="small-btn primary-lite" data-export-site>Download ZIP</button><button class="small-btn" data-download-source>HTML</button>`)+note+`<div class="codebox"><div class="code-toolbar"><span>source.html</span><button class="small-btn" data-copy="${esc(report.source||'')}">Copy</button></div><pre>${esc(report.source||'')}</pre></div>`
}

function renderFiles(){
  const assets=arr(report.page?.assets),publicFiles=arr(report.publicFiles),packs=arr(report.packCandidates)
  const rows=assets.map(a=>`<div class="table-row"><div class="file-type">${esc(a.type)}</div><div class="file-url mono" title="${esc(a.url)}">${esc(a.url)}</div><a class="file-open" href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">Open</a></div>`).join('')
  return head('Files',`${assets.length} linked files`, `<button class="small-btn primary-lite" data-export-site>Download ZIP</button>`)+`${packs.length?`<div class="notice">Pack-looking links: ${packs.map(u=>`<button class="inline-link" data-pack-inspect="${esc(u)}">${esc(u)}</button>`).join(' ')}</div>`:''}<div class="card files-summary"><div class="label">Public files</div>${publicFiles.length?publicFiles.map(f=>row(f.path,`${f.status} · ${f.bytes} bytes`)).join(''):'<div class="muted-inline">No extras found.</div>'}</div><div class="table"><div class="table-row table-head"><div>Type</div><div>URL</div><div></div></div>${rows||'<div class="table-row"><div></div><div>No linked files.</div><div></div></div>'}</div>`
}

function renderNetwork(){
  const n=obj(report.network),d=obj(n.dns),e=obj(n.edge),t=obj(n.timings)
  return head('Network','Public endpoint used for the request.')+`${e.proxied?`<div class="notice warn">${esc(e.note)}</div>`:''}<div class="grid"><div class="card">${row('Host',n.hostname,true,true)}${row('IP',n.address,true,true)}${row('Port',n.port,true,true)}${row('Scheme',n.scheme)}</div><div class="card">${row('Connect',`${fmt(t.connectMs)} ms`)}${row('TLS',t.tlsMs==null?'—':`${t.tlsMs} ms`)}${row('TTFB',`${fmt(t.ttfbMs)} ms`)}${row('Total',`${fmt(t.totalMs)} ms`)}</div><div class="card">${row('Edge',e.provider||'None detected')}${row('TLS',n.tls?.protocol||'—')}${row('ALPN',n.tls?.alpn||'—')}</div><div class="card wide"><div class="label">A</div>${tags(d.a)}<div class="label sublabel">AAAA</div>${tags(d.aaaa)}<div class="label sublabel">CNAME</div>${tags(d.cname)}</div><div class="card wide">${row('MX',arr(d.mx).join(' · '))}${row('Nameservers',arr(d.ns).join(' · '))}${row('PTR',arr(d.ptr).join(' · '))}</div></div>`
}

function renderHeaders(){const headers=obj(report.headers);return head('Headers',`${Object.keys(headers).length} returned`)+`<div class="card">${Object.entries(headers).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>row(k,Array.isArray(v)?v.join(' | '):v,true,true)).join('')}</div>`}
function renderSecurity(){const s=obj(report.security),checks=obj(s.checks);return head('Security','Response header check.')+`<div class="grid"><div class="card"><div class="label">Coverage</div><div class="score">${esc(s.score||0)}%</div></div><div class="card two"><div class="checklist">${Object.entries(checks).map(([k,v])=>`<div class="check ${v?'yes':'no'}">${v?'✓':'·'} ${esc(pretty(k))}</div>`).join('')}</div></div></div>`}

function renderMinecraft(){
  const j=obj(report.java),b=obj(report.bedrock),packs=arr(report.packCandidates)
  return head('Minecraft',report.address||'',`<button class="small-btn" data-download-json>JSON</button>`)+`${packs.length?`<div class="notice pack-found"><strong>Pack found.</strong> ${packs.map(u=>`<button class="small-btn" data-pack-inspect="${esc(u)}">Inspect</button><button class="small-btn primary-lite" data-pack-download="${esc(u)}">Download</button>`).join(' ')}</div>`:`<div class="notice">The status ping did not expose a pack URL. <button class="inline-link" data-open-pack>Paste the pack URL</button> if you have it.</div>`}${mcCard('Java',j)}${mcCard('Bedrock',b)}`
}

function mcCard(name,m){
  const motd=arr(m.motd).join('\n')
  const players=`${fmt(m.playersOnline)} / ${fmt(m.playersMax)}`
  return `<div class="card mc-card"><div class="mc-head">${m.icon?`<img class="mc-icon" src="${esc(m.icon)}" alt="">`:'<div class="mc-icon"></div>'}<div><div class="label">${esc(name)}</div><div class="mc-motd">${esc(motd||(m.online?'Online':'Offline'))}</div><div class="mc-sub">${esc(m.version||'Unknown version')} · ${esc(players)}</div></div></div><div class="mc-rows">${row('Online',m.online?'Yes':'No')}${row('Hostname',m.hostname,true,true)}${row('IP',m.ip,true,true)}${row('Port',m.port,true,true)}${row('Software',m.software)}${row('Gamemode',m.gamemode)}${row('Plugins',arr(m.plugins).length)}${row('Mods',arr(m.mods).length)}</div></div>`
}

function renderPack(){
  const p=obj(report),meta=obj(p.packMeta),pack=obj(meta.pack),entries=arr(p.entries),warnings=arr(p.warnings)
  return head('Resource pack',p.filename||'',`<button class="small-btn primary-lite" data-pack-download="${esc(p.url||'')}">Download ZIP</button><button class="small-btn" data-download-json>JSON</button>`)+`${warnings.length?`<div class="notice warn">${esc(warnings.join(' · '))}</div>`:''}<div class="grid"><div class="card"><div class="label">Files</div><div class="value big">${esc(p.fileCount)}</div></div><div class="card"><div class="label">Download</div><div class="value big">${esc(formatBytes(p.downloadBytes))}</div></div><div class="card"><div class="label">Unpacked</div><div class="value big">${esc(formatBytes(p.uncompressedBytes))}</div></div><div class="card wide">${row('URL',p.url,true,true)}${row('SHA-256',p.sha256,true,true)}${row('Pack format',pack.pack_format)}${row('Description',typeof pack.description==='string'?pack.description:JSON.stringify(pack.description||''))}</div><div class="card wide"><div class="label">Top level</div>${tags(p.folders)}</div></div>${entries.length?`<div class="table pack-table"><div class="table-row table-head"><div>Size</div><div>File</div><div></div></div>${entries.map(x=>`<div class="table-row"><div class="file-type">${esc(formatBytes(x.bytes))}</div><div class="file-url mono" title="${esc(x.name)}">${esc(x.name)}</div><div></div></div>`).join('')}</div>`:''}`
}

function renderRaw(){return head('Raw','API response',`<button class="small-btn" data-download-json>Save JSON</button>`)+`<div class="codebox"><div class="code-toolbar"><span>report.json</span><button class="small-btn" data-copy="${esc(JSON.stringify(report,null,2))}">Copy</button></div><pre>${esc(JSON.stringify(report,null,2))}</pre></div>`}
function hostOf(url){try{return new URL(url).hostname}catch{return''}}
function pretty(value){return String(value).replace(/([A-Z])/g,' $1').replace(/^./,c=>c.toUpperCase())}
function formatBytes(value){const n=Number(value)||0;if(n<1024)return `${n} B`;if(n<1024*1024)return `${(n/1024).toFixed(1)} KB`;return `${(n/1024/1024).toFixed(1)} MB`}
