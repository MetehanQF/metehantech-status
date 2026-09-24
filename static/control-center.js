(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const el = (tag, text, cls) => {const n=document.createElement(tag); if(text!==undefined)n.textContent=text; if(cls)n.className=cls;return n;};
  const fmt = x => x===null||x===undefined||x===''?'UNKNOWN':typeof x==='boolean'?(x?'YES':'NO'):typeof x==='number'?Math.round(x*10)/10:String(x);
  const bytes = n => n==null?'UNKNOWN':(n/1073741824).toFixed(1)+' GiB';
  const status = b => b===true?'RUNNING':b===false?'OFFLINE':'UNKNOWN';
  function card(title,state,fields){const c=el('article',undefined,'panel cc-card');c.append(el('h3',title),el('span',state,'cc-state '+state));const dl=el('dl');for(const [k,v] of Object.entries(fields)){const r=el('div');r.append(el('dt',k),el('dd',fmt(v)));dl.append(r);}c.append(dl);return c;}
  // The hash carries an optional second level ("#dns/clients") so a view with its own
  // sub-navigation survives a refresh. Views without one simply never pass a sub.
  function navigate(view,sub){
    const parts=String(view||'').split('/');view=parts[0];sub=sub===undefined?(parts[1]||''):sub;
    if(!$('view-'+view)){view='overview';sub='';}
    document.querySelectorAll('.cc-view').forEach(v=>v.hidden=v.id!=='view-'+view);
    document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.view===view)));
    history.replaceState(null,'','#'+view+(sub?'/'+sub:''));
    window.ccLoadView?.(view);window.ccSubView?.(view,sub);
    if(view==='systems')window.ccLoadHistory?.();
  }
  window.ccNavigate=navigate;
  document.querySelectorAll('[data-view],[data-open-view]').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.view||b.dataset.openView)));
  function render(d){
    const text=d.health==='HEALTHY'?'ALL SYSTEMS OPERATIONAL':d.health;
    $('cc-health').textContent=text;$('cc-health').className='cc-state '+d.health;
    $('cc-global-status').textContent=text+' · '+(d.alert_counts?`${d.alert_counts.active_critical} critical / ${d.alert_counts.active_warning} warning`:'Alert source UNKNOWN');
    $('cc-global-status').classList.toggle('cc-global-critical',d.health==='CRITICAL');
    // Display only: the banner text and its source data are unchanged, but the accent
    // has to follow the real health so a WARNING state cannot render as healthy green.
    $('cc-global-status').dataset.health=d.health;
    $('cc-age').textContent=d.collection_age_seconds==null?'Collector unavailable · last known database values':`Collector ${Math.round(d.collection_age_seconds)}s ago · ${d.collection_age_seconds>120?'STALE':'60s cadence'}`;
    const devices=d.devices.map(x=>card(x.name,x.health,{Uptime:x.uptime,CPU:x.metrics.cpu,RAM:x.metrics.ram,Temperature:x.metrics.temperature,Freshness:x.freshness}));
    for(const name of ['Home Assistant','Frigate','Nextcloud']){const s=d.services.find(x=>x.name===name);devices.push(card(name,s?.state||'UNKNOWN',{'Status':s?.state||'UNKNOWN'}));}
    const flows=Object.values(d.backup_flows||{}); const ranks=['CRITICAL','WARNING','UNKNOWN','RUNNING','HEALTHY'];
    const backupHealth=ranks.find(k=>flows.some(f=>f.health===k))||'UNKNOWN';
    devices.push(card('Backup',backupHealth,{'Active job':d.backups.active_job?.source_node||'None'}));
    $('cc-backup-flows').replaceChildren(...Object.entries(d.backup_flows||{}).map(([k,f])=>card(k+' → '+fmt(f.destination_node),f.health,{'Last attempt':f.last_attempt?.started_at,'Attempt result':f.last_attempt?.status,'Last verified':f.last_verified?.finished_at,'Verified size':bytes(f.last_verified?.size_bytes),'Verified age (hours)':f.verified_age_hours,'Next run':d.extra.next_backups?.[k]})));
    $('cc-overview').replaceChildren(...devices);
    $('cc-overview-alerts').replaceChildren(...(d.alerts===null?[el('p','Alert source UNKNOWN','cc-alert')]:d.alerts.slice(0,5).map(a=>el('p',a.severity.toUpperCase()+' · '+a.title+' — '+a.message,'cc-alert '+a.severity))));
    $('cc-systems').replaceChildren(...d.devices.map(x=>card(x.name,x.health,{...x.metrics,Uptime:x.uptime,'Metric age (s)':x.metrics_age_seconds,...x.checks})),card('Pi5 details',d.collection_age_seconds>120?'WARNING':d.collection_age_seconds==null?'UNKNOWN':'HEALTHY',{'Hostname':d.extra.hostname,'Load averages':d.extra.load_average?.join(' / '),'Swap %':d.extra.swap_percent,'Network RX/s':d.extra.network?.rx_bytes_per_second==null?null:Math.round(d.extra.network.rx_bytes_per_second)+' B/s','Network TX/s':d.extra.network?.tx_bytes_per_second==null?null:Math.round(d.extra.network.tx_bytes_per_second)+' B/s','Failed units':d.extra.failed_units?.join(', ')|| (d.extra.failed_units?'None':null)}));
    const pd=d.extra.pcold_details||{};$('cc-systems').append(card('PcOld details',pd.hostname?'HEALTHY':'UNKNOWN',{'Hostname':pd.hostname,'Load averages':pd.load_average?.join(' / '),'Network counters':pd.network?Object.entries(pd.network).map(([k,v])=>k+': RX '+bytes(v.rx_bytes)+' / TX '+bytes(v.tx_bytes)).join('; '):null,'Docker container details':'Not exposed by current PcOld agent'}));
    $('cc-services').replaceChildren(...d.services.map(s=>card(s.name,s.state,{})),...(d.extra.systemd||[]).map(s=>card(s.Id,s.ActiveState==='active'?'RUNNING':s.ActiveState==='failed'?'FAILED':'STOPPED',{'Since':s.ActiveEnterTimestamp,'Substate':s.SubState})));
    $('cc-docker').replaceChildren(...(d.extra.containers||[]).map(c=>card(c.name,['healthy','running'].includes(c.state)?'RUNNING':c.state.toUpperCase(),{'Started':c.started_at,'Restart count':c.restart_count,'Health':c.state})),card('PcOld containers','UNKNOWN',{'Details':'Not available from the current monitoring agent'}));
    $('cc-storage').replaceChildren(...d.storage.map(s=>{const c=card(s.name,s.health,{'Used %':s.percent,'Total':bytes(s.total),'Used':bytes(s.used),'Free':bytes(s.free),'SMART':s.smart,'Freshness':s.freshness});if(s.percent!=null){const bar=el('progress');bar.max=100;bar.value=s.percent;bar.setAttribute('aria-label',s.name+' usage');c.append(bar);}return c;}));
    $('cc-network').replaceChildren(...d.network.map(n=>card(n.name,n.freshness==='HEALTHY'?status(n.online):'UNKNOWN',{'Address':n.ip,'Observed':n.observation_time,'Freshness':n.freshness})),card('Topology','UNKNOWN',{'Inventory':'Known infrastructure only','Discovery':'No subnet scans','Latency':'Not measured'}));
    $('cc-next-backups').textContent=Object.entries(d.extra.next_backups||{}).map(([k,v])=>k+': '+fmt(v)).join(' · ')||'UNKNOWN';
    $('cc-person-events').replaceChildren(...(d.extra.person_events||[]).map(e=>el('p',new Date(e.start_time*1000).toLocaleString()+' · person · snapshot available in private Frigate')));
    const c=d.camera;$('cc-camera-detail').replaceChildren(card('Processing',c.processing_paused?'PAUSED':status(c.stream?.available),{'Camera FPS':c.stream?.camera_fps,'Process FPS':c.stream?.process_fps,'Detection FPS':c.stream?.detection_fps,'FFmpeg PID':c.stream?.ffmpeg_pid,'Last motion':c.last_motion,'Person events':'Open private Frigate events','Live playback':'On demand only'}));
    $('cc-cloud-detail').replaceChildren(card('Nextcloud details',status(d.extra.nextcloud?.installed),{'Version':d.extra.nextcloud?.versionstring,'Maintenance':d.extra.nextcloud?.maintenance,'DB upgrade needed':d.extra.nextcloud?.needsDbUpgrade}));
    $('cc-timeline').replaceChildren(...d.timeline.map(r=>{const row=el('div',r.message+' · '+r.result,'cc-timeline-row');row.append(el('small',r.time+' · '+r.source+(r.user?' · '+r.user:'')));return row;}));
  }
  let busy=false;
  async function refresh(){if(busy||document.hidden)return;busy=true;try{const r=await fetch('/api/admin/control-center',{cache:'no-store',signal:AbortSignal.timeout(15000)});if(r.status===401){$('cc-global-status').textContent='Session expired — sign in again';return;}if(!r.ok)throw Error();render(await r.json());}catch{$('cc-health').textContent='UNKNOWN';$('cc-global-status').textContent='UNKNOWN · connection lost; displayed values are last known / STALE';}finally{busy=false;}}
  $('cc-preview-button').addEventListener('click',async()=>{
    $('cc-preview-button').disabled=true;
    try{const r=await fetch('/api/admin/control-center/camera-preview',{cache:'no-store',signal:AbortSignal.timeout(6000)});if(!r.ok)throw Error();const img=$('cc-preview');if(img.dataset.objectUrl)URL.revokeObjectURL(img.dataset.objectUrl);img.dataset.objectUrl=URL.createObjectURL(await r.blob());img.src=img.dataset.objectUrl;img.hidden=false;$('cc-preview-message').textContent='Snapshot loaded on demand';}catch{$('cc-preview-message').textContent='Snapshot unavailable';}finally{$('cc-preview-button').disabled=false;}
  });
  navigate(location.hash.slice(1));refresh();setInterval(refresh,15000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
})();
