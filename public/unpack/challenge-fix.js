(() => {
  const oldOverview = renderOverview
  renderOverview = function(){
    const html = oldOverview()
    if(!report?.access?.challenge)return html
    const provider = report.access.provider || 'Site protection'
    const notice = `<div class="notice warn"><strong>${esc(provider)} blocked the fetch.</strong> Unpack got the challenge page, not the actual site. ZIP export is disabled for this result.</div>`
    return notice + html.replaceAll('data-export-site','data-export-blocked')
  }

  const oldSource = renderSource
  renderSource = function(){
    const html = oldSource()
    if(!report?.access?.challenge)return html
    return `<div class="notice warn">This is the protection page HTML, not the website behind it.</div>` + html.replaceAll('data-export-site','data-export-blocked')
  }

  const oldFiles = renderFiles
  renderFiles = function(){
    const html = oldFiles()
    if(!report?.access?.challenge)return html
    return `<div class="notice warn">Linked files here belong to the challenge page.</div>` + html.replaceAll('data-export-site','data-export-blocked')
  }

  const oldExport = exportSite
  exportSite = async function(){
    if(report?.access?.challenge){
      toast(`${report.access.provider || 'Site protection'} returned a challenge page`)
      return
    }
    return oldExport()
  }

  document.addEventListener('click',e=>{
    if(e.target.closest('[data-export-blocked]'))toast('ZIP disabled for challenge pages')
  })
})()
