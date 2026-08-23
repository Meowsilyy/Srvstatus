(() => {
  const add = () => {
    if (document.querySelector('[data-unpack-link]')) return
    const host = document.querySelector('aside, nav, .sidebar, .settingspanel, .settings-panel') || document.body
    const link = document.createElement('a')
    link.href = 'https://unpack-rx3.onrender.com/'
    link.target = '_blank'
    link.rel = 'noopener noreferrer'
    link.dataset.unpackLink = '1'
    link.textContent = 'Source & files'
    link.title = 'Open Unpack'
    link.style.cssText = 'display:block;margin:10px 12px 2px;padding:7px 9px;border:1px solid rgba(127,127,127,.18);border-radius:7px;color:inherit;text-decoration:none;font-size:12px;opacity:.62;transition:opacity .15s ease'
    link.addEventListener('mouseenter', () => { link.style.opacity = '.92' })
    link.addEventListener('mouseleave', () => { link.style.opacity = '.62' })
    host.appendChild(link)
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', add)
  else add()
})()
