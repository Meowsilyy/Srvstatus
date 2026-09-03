(() => {
  const add = () => {
    if (document.querySelector('[data-unpack-link]')) return
    const link = document.createElement('a')
    link.href = '/unpack'
    link.dataset.unpackLink = '1'
    link.textContent = 'Source & files'
    link.title = 'Open Unpack'
    link.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:90;display:flex;align-items:center;gap:7px;padding:8px 11px;border:1px solid rgba(145,155,165,.24);border-radius:9px;background:rgba(20,23,26,.92);backdrop-filter:blur(10px);color:#c8d0d7;text-decoration:none;font:500 12px/1.2 Inter,system-ui,sans-serif;box-shadow:0 7px 24px rgba(0,0,0,.18);opacity:.68;transition:opacity .15s ease,transform .15s ease'
    link.addEventListener('mouseenter', () => { link.style.opacity = '.96'; link.style.transform = 'translateY(-1px)' })
    link.addEventListener('mouseleave', () => { link.style.opacity = '.68'; link.style.transform = 'none' })
    document.body.appendChild(link)
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', add)
  else add()
})()
