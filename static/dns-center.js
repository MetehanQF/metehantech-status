(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const view = $('view-dns');
  if (!view) return;

  const el = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  };
  const fmt = x => x === null || x === undefined || x === '' ? 'UNKNOWN'
    : typeof x === 'boolean' ? (x ? 'YES' : 'NO')
      : typeof x === 'number' ? Math.round(x * 100) / 100 : String(x);

  function card(title, state, fields) {
    const article = el('article', undefined, 'panel cc-card');
    article.append(el('h3', title), el('span', state, 'cc-state ' + state));
    const list = el('dl');
    for (const [key, value] of Object.entries(fields)) {
      const row = el('div');
      row.append(el('dt', key), el('dd', fmt(value)));
      list.append(row);
    }
    article.append(list);
    return article;
  }

  function rows(table, items, build, decorate) {
    const body = $(table).tBodies[0];
    if (!items || !items.length) {
      const empty = el('tr');
      const cell = el('td', 'No data yet.');
      cell.colSpan = $(table).tHead.rows[0].cells.length;
      empty.append(cell);
      body.replaceChildren(empty);
      return;
    }
    body.replaceChildren(...items.map(item => {
      const row = el('tr');
      for (const cell of build(item)) {
        row.append(cell instanceof Node ? cell : el('td', cell));
      }
      if (decorate) decorate(row, item);
      return row;
    }));
  }

  /** Right-aligned, tabular-numeral cell. */
  const num = text => el('td', text, 'numeric');
  /** Long values (domains, upstream URLs) may wrap instead of widening the table. */
  const wrap = text => el('td', text, 'dns-wrap');

  const count = value => typeof value === 'number' ? value.toLocaleString() : '—';
  const percent = value => value === null || value === undefined ? '—' : value + '%';
  const ms = value => value === null || value === undefined ? null : value + ' ms';

  /** Turns a row into a keyboard-operable control that opens a detail drawer. */
  function clickable(row, open) {
    row.classList.add('is-clickable');
    row.tabIndex = 0;
    row.setAttribute('role', 'button');
    row.addEventListener('click', open);
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); }
    });
  }

  const CATEGORY_LABEL = {
    infrastructure: 'Infrastructure',
    user_device: 'User device',
    iot: 'IoT',
    unknown: 'Unknown',
  };

  // ------------------------------------------------------------------- drawer
  // One drawer implementation shared by the client, domain, query and resolver
  // details. It is appended to <body> rather than into the DNS view so it is not
  // affected by the view's [hidden] state, and it restores focus on close.
  const drawer = (() => {
    let scrim = null;
    let panel = null;
    let restoreFocus = null;

    function close() {
      if (!panel) return;
      panel.remove();
      scrim.remove();
      panel = scrim = null;
      document.removeEventListener('keydown', onKey);
      if (restoreFocus && restoreFocus.isConnected) restoreFocus.focus();
      restoreFocus = null;
    }

    function onKey(event) {
      if (event.key === 'Escape') { event.preventDefault(); close(); }
    }

    function open(title, subtitle) {
      close();
      restoreFocus = document.activeElement;
      scrim = el('div', undefined, 'dns-drawer-scrim');
      scrim.addEventListener('click', close);

      panel = el('aside', undefined, 'dns-drawer');
      panel.setAttribute('role', 'dialog');
      panel.setAttribute('aria-modal', 'true');
      panel.setAttribute('aria-label', title);
      panel.tabIndex = -1;

      const head = el('div', undefined, 'dns-drawer-head');
      const heading = el('div');
      heading.append(el('h3', title));
      if (subtitle) heading.append(el('p', subtitle));
      const closeButton = el('button', '✕', 'dns-drawer-close');
      closeButton.type = 'button';
      closeButton.setAttribute('aria-label', 'Close detail');
      closeButton.addEventListener('click', close);
      head.append(heading, closeButton);

      const body = el('div', undefined, 'dns-drawer-body');
      panel.append(head, body);
      document.body.append(scrim, panel);
      document.addEventListener('keydown', onKey);
      panel.focus();
      return body;
    }

    return { open, close };
  })();

  /** Definition list block. A null value renders "Not available"; undefined is skipped. */
  function detail(title, fields) {
    const block = el('div');
    if (title) block.append(el('h4', title));
    const entries = Object.entries(fields).filter(([, value]) => value !== undefined);
    if (!entries.length) {
      block.append(el('p', 'Not available.', 'dns-drawer-empty'));
      return block;
    }
    const list = el('dl');
    for (const [key, value] of entries) {
      const row = el('div');
      const blank = value === null || value === '';
      row.append(el('dt', key), el('dd', blank ? 'Not available' : String(value)));
      list.append(row);
    }
    block.append(list);
    return block;
  }

  function ranking(title, items, emptyText) {
    const block = el('div');
    block.append(el('h4', title));
    if (!items || !items.length) {
      block.append(el('p', emptyText, 'dns-drawer-empty'));
      return block;
    }
    const list = el('dl');
    for (const item of items.slice(0, 10)) {
      const row = el('div');
      row.append(el('dt', item.key), el('dd', count(item.count)));
      list.append(row);
    }
    block.append(list);
    return block;
  }

  const accentFor = state => state === 'HEALTHY' ? 'ok'
    : state === 'DEGRADED' || state === 'WARNING' ? 'warn'
      : state === 'CRITICAL' ? 'crit' : null;

  // ------------------------------------------------------ sub-navigation
  // The DNS view has its own second level. The selected section lives in the URL
  // hash ("#dns/clients") so a refresh returns to the same place, and every polling
  // loop asks `active` before doing any work.
  const SECTIONS = ['overview', 'traffic', 'clients', 'domains', 'resolvers', 'querylog'];
  let section = 'overview';
  const active = name => !view.hidden && section === name;

  function showSection(name) {
    section = SECTIONS.includes(name) ? name : 'overview';
    for (const id of SECTIONS) {
      const node = $('dns-section-' + id);
      if (node) node.hidden = id !== section;
    }
    for (const button of $('dns-subnav').querySelectorAll('button')) {
      button.setAttribute('aria-pressed', String(button.dataset.dns === section));
    }
    if (section === 'querylog' && !recentLoaded) { recentLoaded = true; loadRecent(false); }
    if (section === 'overview' && !eventsLoaded) { eventsLoaded = true; loadEvents(); }
    // The canvas has no layout while hidden, so it is drawn on entry, not on update.
    if (section === 'traffic') drawTraffic();
    syncLive();
  }

  $('dns-subnav').addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button) return;
    if (window.ccNavigate) window.ccNavigate('dns', button.dataset.dns);
    else showSection(button.dataset.dns);
  });
  window.ccSubView = (viewName, sub) => { if (viewName === 'dns') showSection(sub || 'overview'); };

  // ---------------------------------------------------------- health strip
  function strip(label, value, state) {
    const item = el('div', undefined, 'dns-strip-item' + (state ? ' state-' + state : ''));
    item.append(el('span', label, 'dns-strip-label'),
      el('strong', value === null || value === undefined ? 'n/a' : String(value), 'dns-strip-value'));
    return item;
  }

  function renderStrip(data) {
    const cluster = data.cluster || {};
    const cache = data.cache || {};
    const upstreams = data.upstreams;
    const health = data.health || 'UNKNOWN';

    const lead = el('div', undefined, 'dns-strip-lead state-' + (accentFor(health) || 'idle'));
    lead.append(el('span', 'DNS HEALTH', 'dns-strip-label'), el('strong', health, 'dns-strip-state'));

    const members = (cluster.members || []).map(member => strip(
      member.label || member.node,
      member.latency_ms === null || member.latency_ms === undefined
        ? 'not probed' : member.latency_ms + ' ms',
      accentFor(member.health)));

    const healthyUpstreams = upstreams ? upstreams.filter(item => item.healthy).length : null;

    $('dns-health-strip').replaceChildren(
      lead,
      ...members,
      strip('Cache', cache.hit_percent === null || cache.hit_percent === undefined
        ? null : cache.hit_percent + '%', 'live'),
      strip('Blocked', data.blocked_percent === null || data.blocked_percent === undefined
        ? null : data.blocked_percent + '%', 'crit'),
      strip('Upstreams', upstreams ? healthyUpstreams + '/' + upstreams.length : null,
        upstreams === null || upstreams === undefined ? null
          : healthyUpstreams === upstreams.length ? 'ok'
            : healthyUpstreams ? 'warn' : 'crit'),
      strip('Probe', cluster.collection_age_seconds === null || cluster.collection_age_seconds === undefined
        ? null : Math.round(cluster.collection_age_seconds) + 's ago'),
    );
  }

  // ------------------------------------------------------------- anomalies
  // Rendered only from the measurement the backend actually took. When the measured
  // rate falls back under the threshold the backend stops reporting it and the card
  // disappears on the next refresh — there is no sticky state to clear.
  function renderAnomalies(data) {
    const findings = data.anomalies || [];
    const container = $('dns-anomalies');
    if (!findings.length) { container.replaceChildren(); return; }
    const window_ = data.anomaly_window || {};
    container.replaceChildren(...findings.map(finding => {
      const item = el('article', undefined, 'panel dns-anomaly');
      const head = el('div', undefined, 'dns-anomaly-head');
      head.append(el('span', 'ANOMALY', 'dns-anomaly-tag'),
        el('span', finding.kind === 'repetitive_domain'
          ? 'High repetitive DNS traffic' : 'High query rate', 'dns-anomaly-kind'));
      item.append(head);
      const client = el('h3', finding.client);
      item.append(client);
      const facts = el('div', undefined, 'dns-anomaly-facts');
      facts.append(
        el('span', finding.queries_per_minute + ' queries/min'),
        ...(finding.domain ? [el('span', finding.domain, 'dns-anomaly-domain')] : []),
        ...(finding.share_percent !== null && finding.share_percent !== undefined
          ? [el('span', finding.share_percent + '% of its queries')] : []),
        el('span', finding.sample_queries + ' queries over '
          + Math.round(finding.sample_span_seconds / 60) + ' min'),
      );
      item.append(facts);
      item.append(el('p', 'Observation only — measured from the retained query log. '
        + 'Nothing is blocked, rewritten or reconfigured, and this card clears itself '
        + 'when the measured rate drops below '
        + (window_.thresholds ? window_.thresholds.repetition_rate_per_minute : '—')
        + ' queries/min.', 'dns-note'));
      const open = el('button', 'Open client detail', 'dns-link');
      open.type = 'button';
      open.addEventListener('click', () => clientDrawer(finding.client, null));
      item.append(open);
      return item;
    }));
  }

  // ---------------------------------------------------------------- KPI strip
  function kpi(label, value, note, accent) {
    const tile = el('div', undefined, 'dns-kpi' + (accent ? ' accent-' + accent : ''));
    tile.append(el('span', label, 'dns-kpi-label'));
    const blank = value === null || value === undefined || value === '';
    tile.append(el('strong', blank ? 'Not available' : value,
      'kpi-value' + (blank ? ' is-unavailable' : '')));
    if (note) tile.append(el('span', note, 'dns-kpi-note'));
    return tile;
  }

  function renderKpis(data) {
    const cache = data.cache || {};
    const latency = data.latency || {};
    const cluster = data.cluster || {};
    // AdGuard's `time_units` is the bucket granularity, not the window. The real window
    // is how many buckets it kept, so derive the label from the series it actually sent.
    const traffic_ = data.traffic || {};
    const span = (() => {
      if (!traffic_.buckets || !traffic_.units) return 'AdGuard counter';
      if (traffic_.units === 'hours') {
        return traffic_.buckets % 24 === 0
          ? 'AdGuard counter · last ' + traffic_.buckets / 24 + ' days'
          : 'AdGuard counter · last ' + traffic_.buckets + ' hours';
      }
      return 'AdGuard counter · last ' + traffic_.buckets + ' ' + traffic_.units;
    })();
    const window_ = span;
    const optional = value => value === null || value === undefined ? null : value;

    $('dns-kpis').replaceChildren(
      kpi('Queries', optional(data.queries) === null ? null : data.queries.toLocaleString(), window_),
      kpi('Blocked', optional(data.blocked) === null ? null : data.blocked.toLocaleString(), window_, 'crit'),
      kpi('Blocked %', optional(data.blocked_percent) === null ? null : data.blocked_percent + '%', window_, 'crit'),
      kpi('Cache hit %', optional(cache.hit_percent) === null ? null : cache.hit_percent + '%',
        cache.sample_size ? 'measured over ' + cache.sample_size + ' queries' : 'no sample yet', 'live'),
      kpi('Avg response', optional(data.avg_processing_ms) === null ? null : data.avg_processing_ms + ' ms',
        'AdGuard lifetime mean'),
      kpi('P95 response', optional(latency.p95_ms) === null ? null : latency.p95_ms + ' ms',
        latency.sample_size ? 'measured over ' + latency.sample_size + ' queries' : 'no sample yet'),
      kpi('Active clients', optional(data.active_clients) === null ? null : String(data.active_clients),
        'seen in the statistics window'),
      kpi('Resolver health',
        cluster.total && cluster.healthy !== null && cluster.healthy !== undefined
          ? cluster.healthy + ' / ' + cluster.total : null,
        cluster.state ? cluster.state.toLowerCase() + (cluster.redundant === false ? ' · no redundancy' : '')
          : 'not probed yet',
        accentFor(cluster.state)),
    );
  }

  // ----------------------------------------------------------- traffic graph
  // AdGuard returns equal-length counter arrays ordered oldest -> newest, one entry
  // per time unit. The chart is drawn once per data change / range change / resize —
  // there is no animation loop and no rendering while the section is hidden.
  const traffic = { buckets: 24, data: null, geometry: null };

  function trafficSlice() {
    const source = traffic.data;
    if (!source || !Array.isArray(source.queries) || !source.queries.length) return null;
    const size = Math.min(traffic.buckets, source.queries.length);
    const start = source.queries.length - size;
    return {
      queries: source.queries.slice(start),
      blocked: (source.blocked || []).slice(start),
    };
  }

  function niceMax(peak) {
    const step = Math.pow(10, Math.floor(Math.log10(peak)));
    for (const factor of [1, 2, 2.5, 5, 10]) {
      if (step * factor >= peak) return step * factor;
    }
    return step * 10;
  }

  const compact = value => value >= 1000
    ? Math.round(value / 100) / 10 + 'k' : String(Math.round(value));

  function renderTrafficStats(slice) {
    const container = $('dns-traffic-stats');
    if (!container) return;
    if (!slice || !slice.queries.length) { container.replaceChildren(); return; }
    const queries = slice.queries;
    const blocked = slice.blocked.length === queries.length ? slice.blocked : [];
    const total = queries.reduce((sum, value) => sum + value, 0);
    const peak = Math.max(...queries);
    const peakBlocked = blocked.length ? Math.max(...blocked) : null;
    const average = Math.round(total / queries.length);
    const unit = queries.length === 1 ? 'the current hourly bucket'
      : queries.length + ' hourly buckets';
    container.replaceChildren(
      kpi('Peak queries/hour', peak.toLocaleString(), unit),
      kpi('Peak blocked/hour', peakBlocked === null ? null : peakBlocked.toLocaleString(),
        blocked.length ? unit : 'no blocked series for this range', 'crit'),
      kpi('Average queries/hour', average.toLocaleString(), unit),
      kpi('Range total', total.toLocaleString(), unit),
    );
  }

  function drawTraffic() {
    const canvas = $('dns-traffic-canvas');
    const empty = $('dns-traffic-empty');
    const caption = $('dns-traffic-total');
    const slice = trafficSlice();
    const hasData = !!slice && slice.queries.some(value => value > 0);

    const label = $('dns-traffic-window');
    if (label) {
      label.textContent = traffic.data && traffic.data.buckets
        ? traffic.data.buckets + ' ' + (traffic.data.units || 'buckets')
        : 'no published history';
    }

    canvas.hidden = !hasData;
    empty.hidden = hasData;
    traffic.geometry = null;
    hideTip();
    renderTrafficStats(hasData ? slice : null);
    if (!hasData) {
      empty.textContent = traffic.data
        ? 'No queries recorded in this range — AdGuard reported zero for every bucket.'
        : 'Not available — AdGuard has not published a traffic history yet.';
      caption.textContent = traffic.data ? 'NO TRAFFIC IN RANGE' : 'UNKNOWN';
      return;
    }

    const total = slice.queries.reduce((sum, value) => sum + value, 0);
    const blocked = slice.blocked.reduce((sum, value) => sum + (value || 0), 0);
    caption.textContent = total.toLocaleString() + ' queries · ' + blocked.toLocaleString() + ' blocked';

    const context = canvas.getContext('2d');
    if (!context) return;
    const style = getComputedStyle(document.documentElement);
    const read = (name, fallback) => style.getPropertyValue(name).trim() || fallback;
    const live = read('--cyan', '#22d3ee');
    const critical = read('--crit', '#f87171');
    const muted = read('--text-3', '#8a83a0');

    const width = Math.max(1, Math.floor(canvas.clientWidth));
    const height = Math.max(1, Math.floor(canvas.clientHeight));
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);
    context.font = '11px Inter, system-ui, sans-serif';
    context.textBaseline = 'middle';

    const bounds = { left: 48, right: width - 12, top: 14, bottom: height - 26 };
    if (bounds.right <= bounds.left || bounds.bottom <= bounds.top) return;

    const size = slice.queries.length;
    const max = niceMax(Math.max(...slice.queries, 1));
    const x = index => size === 1 ? (bounds.left + bounds.right) / 2
      : bounds.left + index / (size - 1) * (bounds.right - bounds.left);
    const y = value => bounds.bottom - (value / max) * (bounds.bottom - bounds.top);

    context.lineWidth = 1;
    context.strokeStyle = 'rgba(167, 139, 250, 0.10)';
    context.fillStyle = muted;
    context.textAlign = 'right';
    for (let line = 0; line <= 4; line += 1) {
      const value = max * (1 - line / 4);
      const at = y(value);
      context.beginPath();
      context.moveTo(bounds.left, at);
      context.lineTo(bounds.right, at);
      context.stroke();
      context.fillText(compact(value), bounds.left - 8, at);
    }

    // Bucket n-1 is the current, still-filling hour.
    const now = Date.now();
    const stampOf = index => new Date(now - (size - 1 - index) * 3600000);
    const labelOf = date => traffic.buckets > 48
      ? date.toLocaleDateString([], { day: 'numeric', month: 'short' })
      : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    context.textAlign = 'center';
    const step = Math.max(1, Math.ceil(size / 6));
    for (let index = size - 1; index >= 0; index -= step) {
      context.fillText(labelOf(stampOf(index)), x(index), bounds.bottom + 14);
    }

    const area = context.createLinearGradient(0, bounds.top, 0, bounds.bottom);
    area.addColorStop(0, 'rgba(34, 211, 238, 0.30)');
    area.addColorStop(1, 'rgba(34, 211, 238, 0)');
    context.beginPath();
    context.moveTo(x(0), bounds.bottom);
    slice.queries.forEach((value, index) => context.lineTo(x(index), y(value)));
    context.lineTo(x(size - 1), bounds.bottom);
    context.closePath();
    context.fillStyle = area;
    context.fill();

    const line = (values, colour, thickness) => {
      context.beginPath();
      values.forEach((value, index) => {
        const point = typeof value === 'number' ? value : 0;
        if (index === 0) context.moveTo(x(index), y(point));
        else context.lineTo(x(index), y(point));
      });
      context.strokeStyle = colour;
      context.lineWidth = thickness;
      context.lineJoin = 'round';
      context.stroke();
    };
    line(slice.queries, live, 2);
    if (slice.blocked.length === size) line(slice.blocked, critical, 1.6);

    // A single bucket has no line to draw, so the one real value is marked instead.
    if (size === 1) {
      context.beginPath();
      context.arc(x(0), y(slice.queries[0]), 4, 0, Math.PI * 2);
      context.fillStyle = live;
      context.fill();
    }

    traffic.geometry = { bounds, size, slice, x, y, stampOf };
  }

  // Tooltip: reads the geometry the last draw recorded, so hovering never redraws.
  function hideTip() {
    const tip = $('dns-traffic-tip');
    if (tip) tip.hidden = true;
  }

  function showTip(event) {
    const geometry = traffic.geometry;
    const tip = $('dns-traffic-tip');
    const canvas = $('dns-traffic-canvas');
    if (!geometry || !tip || canvas.hidden) return;
    const box = canvas.getBoundingClientRect();
    const position = event.clientX - box.left;
    const { bounds, size, slice } = geometry;
    if (position < bounds.left - 12 || position > bounds.right + 12) { hideTip(); return; }
    const ratio = size === 1 ? 0
      : (position - bounds.left) / Math.max(1, bounds.right - bounds.left);
    const index = Math.max(0, Math.min(size - 1, Math.round(ratio * (size - 1))));
    const queries = slice.queries[index];
    const blocked = slice.blocked.length === size ? slice.blocked[index] : null;
    tip.replaceChildren(
      el('strong', geometry.stampOf(index).toLocaleString([], {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
      })),
      el('span', count(queries) + ' queries'),
      el('span', blocked === null ? 'blocked: not available'
        : count(blocked) + ' blocked · '
          + (queries ? Math.round(blocked / queries * 1000) / 10 : 0) + '%'),
    );
    tip.hidden = false;
    const left = Math.max(0, Math.min(box.width - tip.offsetWidth - 4, geometry.x(index) - tip.offsetWidth / 2));
    tip.style.left = left + 'px';
  }

  // ---------------------------------------------------------------- topology
  function topoStage(label, nodes, isLive) {
    const stage = el('div', undefined, 'dns-topo-stage' + (isLive ? ' is-live' : ''));
    stage.append(el('span', label, 'dns-kpi-label'), ...nodes);
    return stage;
  }

  function topoNode(title, meta, state, open) {
    const node = el('button', undefined, 'dns-node' + (state ? ' state-' + state : ''));
    node.type = 'button';
    node.append(el('span', title, 'dns-node-title'), el('span', meta, 'dns-node-meta'));
    if (open) node.addEventListener('click', open); else node.disabled = true;
    return node;
  }

  function resolverDrawer(member) {
    const body = drawer.open(member.label || member.node,
      (member.address || '') + ':53 · ' + (member.role || 'resolver'));
    body.append(detail('Probe result', {
      'Role': member.role || null,
      'Address': member.address ? member.address + ':53' : null,
      'Health': member.health || null,
      'Answering': member.answering === null || member.answering === undefined
        ? null : (member.answering ? 'YES' : 'NO'),
      'Still filtering': member.filtering === null || member.filtering === undefined
        ? null : (member.filtering ? 'YES' : 'NO'),
      'Probe latency': ms(member.latency_ms),
      'State': member.detail || null,
    }));
    body.append(el('p', 'Health is two real DNS queries per collector cycle: one that must '
      + 'resolve and one that must still be blocked. It is not a port check.', 'dns-note'));
  }

  function upstreamDrawer(upstream, extra) {
    const body = drawer.open(upstream.address, upstream.role === 'fallback'
      ? 'Fallback resolver — answers only when every primary upstream has failed'
      : 'Configured upstream resolver');
    body.append(detail('Probe', {
      'Role': upstream.role || null,
      'Health': upstream.healthy ? 'HEALTHY' : 'CRITICAL',
      'Result': upstream.healthy ? 'OK' : (upstream.detail || 'FAILED'),
      'Last probe': extra.checkedAt ? new Date(extra.checkedAt * 1000).toLocaleString() : null,
    }));
    body.append(detail('Observed traffic · AdGuard counters', {
      'Responses': extra.responses === undefined ? null : count(extra.responses),
      'Average response': extra.average === undefined ? null : ms(extra.average),
    }));
    body.append(el('p', 'Read from the running AdGuard configuration. This dashboard does '
      + 'not change upstream, fallback or bootstrap settings.', 'dns-note'));
  }

  function renderTopology(data) {
    const cluster = data.cluster || {};
    const members = cluster.members || [];
    const upstreams = data.upstreams;
    const upstreamState = upstreams === null || upstreams === undefined ? null
      : upstreams.every(item => item.healthy) ? 'ok'
        : upstreams.some(item => item.healthy) ? 'warn' : 'crit';
    const healthyUpstreams = (upstreams || []).filter(item => item.healthy).length;
    const serving = typeof cluster.serving === 'number' ? cluster.serving : null;
    const live = serving !== null && serving > 0;

    const resolverNodes = members.length
      ? members.map(member => topoNode(
        member.label || member.node,
        (member.address || '') + ':53 · '
          + (member.answering === null || member.answering === undefined ? 'not probed'
            : (member.answering ? 'answering' : 'no answer'))
          + ' · ' + (member.filtering ? 'filtering' : 'not filtering')
          + ' · ' + (member.latency_ms === null || member.latency_ms === undefined
            ? 'latency unknown' : member.latency_ms + ' ms'),
        accentFor(member.health),
        () => resolverDrawer(member)))
      : [topoNode('Resolvers', 'not probed yet', null, null)];

    const upstreamNodes = (upstreams || []).map(upstream => topoNode(
      upstream.address,
      (upstream.role === 'fallback' ? 'fallback · ' : 'upstream · ')
        + (upstream.healthy ? 'healthy' : (upstream.detail || 'failed')),
      upstream.healthy ? 'ok' : 'crit',
      () => upstreamDrawer(upstream, { checkedAt: data.upstreams_checked_at })));

    $('dns-topology').replaceChildren(
      topoStage('LAN CLIENTS', [topoNode(
        'LAN clients',
        data.active_clients === null || data.active_clients === undefined
          ? 'client count unknown'
          : data.active_clients + ' clients in the statistics window',
        live ? 'live' : null,
        null)], live),
      // The dashboard never queries the router, so this node deliberately carries no
      // health state and claims nothing about the router's own configuration.
      // Adres API yanitindan gelir (dns_center.summary -> gateway_address);
      // istemci kodunda sabit tutulmaz.
      topoStage('GATEWAY', [topoNode(
        data.gateway_address ? 'Router · ' + data.gateway_address : 'Router',
        'LAN gateway · not health-probed by this dashboard',
        null,
        null)], false),
      topoStage('RESOLVERS', resolverNodes, live),
      topoStage('CACHE / FILTER', [topoNode(
        'Cache & filtering',
        (data.protection_enabled === true ? 'filtering ON' :
          data.protection_enabled === false ? 'filtering OFF' : 'filtering unknown')
        + ' · cache hit '
        + ((data.cache || {}).hit_percent === null || (data.cache || {}).hit_percent === undefined
          ? 'unknown' : data.cache.hit_percent + '%'),
        data.protection_enabled === true ? 'live'
          : data.protection_enabled === false ? 'warn' : null,
        null)], live),
      topoStage('UPSTREAM', upstreamNodes.length ? upstreamNodes : [topoNode(
        'Upstreams', 'upstream probe not completed yet', null, null)],
      upstreamState === 'ok'),
      topoStage('INTERNET', [topoNode(
        'Internet',
        upstreams === null || upstreams === undefined
          ? 'upstream probe not completed yet'
          : healthyUpstreams + ' / ' + upstreams.length + ' upstreams healthy',
        upstreamState,
        null)], upstreamState === 'ok'),
    );
  }

  // ------------------------------------------------------- client drawer
  async function clientDrawer(address, fallbackName) {
    const body = drawer.open(fallbackName || 'Unknown client', address);
    body.append(el('p', 'Loading client detail…', 'dns-drawer-empty'));
    let payload = null;
    try {
      const response = await fetch('/api/admin/dns-center/client?address='
        + encodeURIComponent(address), { cache: 'no-store', signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error();
      payload = await response.json();
    } catch {
      body.replaceChildren(el('p', 'Client detail unavailable — AdGuard did not answer.',
        'dns-drawer-empty'));
      return;
    }
    if (!body.isConnected) return;   // drawer was closed while the request was in flight

    const lifetime = payload.lifetime || {};
    const sample = payload.sample || {};
    const identity = payload.identity || {};

    const blocks = [
      detail('Identity', {
        'Hostname': lifetime.name || identity.name || null,
        'Name source': lifetime.name_source || identity.name_source || null,
        'Current IP': payload.address,
        'Category': identity.category ? CATEGORY_LABEL[identity.category] || identity.category : null,
        'Category evidence': identity.category_source || null,
        'Infrastructure role': identity.infrastructure_role || null,
        'MAC address': identity.mac || null,
        'MAC kind': identity.mac === null || identity.mac === undefined ? null
          : (identity.mac_randomised ? 'randomised / locally administered'
            : 'universally administered'),
        'Known IPs': identity.known_addresses ? identity.known_addresses.join(' · ') : null,
        'Identity evidence': identity.identity_source || null,
      }),
    ];

    // Same hostname on another address is reported, never silently merged.
    if (identity.duplicate_candidates && identity.duplicate_candidates.length) {
      blocks.push(detail('Same hostname, not merged', Object.fromEntries(
        identity.duplicate_candidates.map(item => [item.address, item.reason]))));
    }

    blocks.push(
      detail('Totals · AdGuard statistics', {
        'Queries': count(lifetime.queries),
        'Blocked': count(lifetime.blocked),
        'Blocked %': percent(lifetime.blocked_percent),
      }),
      // A saturated sample says so, so a capped count is never read as a total.
      detail(sample.size && sample.size >= sample.requested
        ? 'Retained query log · newest ' + sample.size + ' (sample limit)'
        : 'Retained query log · sample of ' + (sample.size || 0), {
        'Last seen': sample.last_seen ? new Date(sample.last_seen).toLocaleString() : null,
        'Queries in sample': count(sample.size),
        'Blocked in sample': count(sample.blocked),
        'Blocked % in sample': percent(sample.blocked_percent),
      }),
      ranking('Top queried domains', payload.top_queried_domains,
        'No queries for this client in the retained log.'),
      ranking('Top blocked domains', payload.top_blocked_domains,
        'Nothing blocked for this client in the retained log.'),
    );

    if (payload.recent && payload.recent.length) {
      const recentBlock = el('div');
      recentBlock.append(el('h4', 'Recent queries'));
      const list = el('dl');
      for (const item of payload.recent) {
        const row = el('div');
        row.append(el('dt', (item.time ? new Date(item.time).toLocaleTimeString() : '—')
          + ' · ' + (item.name || '—')),
        el('dd', (item.blocked ? 'BLOCKED' : (item.status || '—'))
          + (item.cached ? ' · cached' : '')));
        list.append(row);
      }
      recentBlock.append(list);
      blocks.push(recentBlock);
    }

    body.replaceChildren(...blocks);
  }

  // ------------------------------------------------------- domain drawer
  async function domainDrawer(name) {
    const body = drawer.open(name, 'Retained query log');
    body.append(el('p', 'Loading domain detail…', 'dns-drawer-empty'));
    let payload = null;
    try {
      const response = await fetch('/api/admin/dns-center/domain?name='
        + encodeURIComponent(name), { cache: 'no-store', signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error();
      payload = await response.json();
    } catch {
      body.replaceChildren(el('p', 'Domain detail unavailable — AdGuard did not answer.',
        'dns-drawer-empty'));
      return;
    }
    if (!body.isConnected) return;

    const sample = payload.sample || {};
    const lifetime = payload.lifetime || {};
    const blocks = [
      detail('Domain', {
        'Domain': payload.domain,
        'Queries · AdGuard counter': lifetime.queries === undefined ? null : count(lifetime.queries),
        'Blocked · AdGuard counter': lifetime.blocked === undefined ? null : count(lifetime.blocked),
      }),
      detail(sample.size && sample.size >= sample.requested
        ? 'Retained query log · newest ' + sample.size + ' (sample limit)'
        : 'Retained query log · sample of ' + (sample.size || 0), {
        'Last seen': sample.last_seen ? new Date(sample.last_seen).toLocaleString() : null,
        'Oldest in sample': sample.first_seen ? new Date(sample.first_seen).toLocaleString() : null,
        'Blocked in sample': count(sample.blocked),
        'Blocked % in sample': percent(sample.blocked_percent),
        'Cached in sample': count(sample.cached),
      }),
      ranking('Query types', payload.query_types, 'No query types in the retained log.'),
      ranking('Top clients', payload.top_clients, 'No client asked for this in the retained log.'),
    ];
    if (payload.matched_rules && payload.matched_rules.length) {
      blocks.push(ranking('Matched filter rules', payload.matched_rules, ''));
    }
    blocks.push(el('p', 'Traffic observation only. This dashboard does not classify a '
      + 'domain as safe or malicious — nothing here measures that.', 'dns-note'));
    body.replaceChildren(...blocks);
  }

  function queryDrawer(item) {
    const body = drawer.open(item.name || 'Query',
      (item.client_name || item.client || 'Unknown client')
      + (item.type ? ' · ' + item.type : ''));
    const result = item.blocked ? 'BLOCKED' : (item.status || null);
    body.append(detail('Query', {
      'Timestamp': item.time ? new Date(item.time).toLocaleString() : null,
      'Domain': item.name || null,
      'Query type': item.type || null,
      'Result': result,
      'Reason': item.reason || null,
      'Cached': item.cached ? 'YES' : 'NO',
      'DNSSEC validated': item.dnssec === null || item.dnssec === undefined
        ? null : (item.dnssec ? 'YES' : 'NO'),
    }));
    body.append(detail('Client', {
      'Client': item.client_name || null,
      'IP': item.client || null,
    }));
    body.append(detail('Resolution', {
      // AdGuard reports the upstream only for a query it actually forwarded; a cached
      // or filtered answer legitimately has none, so this stays "Not available".
      'Resolver / upstream': item.upstream || null,
      'Processing time': ms(item.elapsed_ms),
    }));
    if (item.rules && item.rules.length) {
      body.append(detail('Matched filter rules',
        Object.fromEntries(item.rules.map((rule, index) => ['Rule ' + (index + 1), rule]))));
    }
    if (item.answers && item.answers.length) {
      body.append(detail('Answer',
        Object.fromEntries(item.answers.map((value, index) => ['Record ' + (index + 1), value]))));
    }
    const openClient = el('button', 'View this client', 'dns-link');
    openClient.type = 'button';
    openClient.addEventListener('click', () =>
      clientDrawer(item.client, item.client_name));
    if (item.client) body.append(openClient);
  }

  // ------------------------------------------------------------- client view
  const clientView = { search: '', category: 'all', scope: 'all', data: [] };

  function scopeOf(item) {
    return (item.category || (item.identity || {}).category || 'unknown') === 'infrastructure'
      ? 'infrastructure' : 'client';
  }

  function visibleClients() {
    const needle = clientView.search.toLowerCase();
    return clientView.data.filter(item => {
      const category = item.category || (item.identity || {}).category || 'unknown';
      if (clientView.category !== 'all' && category !== clientView.category) return false;
      if (clientView.scope !== 'all' && scopeOf(item) !== clientView.scope) return false;
      if (!needle) return true;
      return String(item.key || '').toLowerCase().includes(needle)
        || String(item.name || '').toLowerCase().includes(needle);
    });
  }

  function renderClients() {
    const share = item => typeof item.count === 'number' && item.count > 0
      && typeof item.blocked === 'number'
      ? Math.round(item.blocked / item.count * 1000) / 10 : null;

    const visible = visibleClients();
    const totals = visible.reduce((acc, item) => {
      acc.queries += typeof item.count === 'number' ? item.count : 0;
      acc.blocked += typeof item.blocked === 'number' ? item.blocked : 0;
      return acc;
    }, { queries: 0, blocked: 0 });

    $('dns-scope-summary').textContent = visible.length
      ? visible.length + ' of ' + clientView.data.length + ' listed clients · '
        + totals.queries.toLocaleString() + ' queries · '
        + totals.blocked.toLocaleString() + ' blocked in this view. '
        + 'These subtotals are the dashboard view only — AdGuard’s own counters and '
        + 'DNS behaviour are untouched by this filter.'
      : 'No client in the bounded top-client list matches this filter.';

    rows('dns-clients', visible, item => {
      const identity = item.identity || {};
      const category = item.category || identity.category || 'unknown';
      const cell = el('td');
      cell.append(el('span', CATEGORY_LABEL[category] || category,
        'dns-badge category-' + category));
      if (identity.duplicate_candidates && identity.duplicate_candidates.length) {
        const flag = el('span', 'DUPLICATE?', 'dns-badge warn');
        flag.title = 'Another address reports the same hostname. Not merged: '
          + identity.duplicate_candidates[0].reason;
        cell.append(flag);
      }
      return [
        item.name || 'Unknown client',
        item.key,
        num(count(item.count)),
        num(item.blocked === undefined ? '—' : count(item.blocked)),
        num(percent(share(item))),
        cell,
        item.name_source || '—',
      ];
    }, (row, item) => clickable(row, () => clientDrawer(item.key, item.name)));
  }

  $('dns-client-search').addEventListener('input', event => {
    clientView.search = event.target.value.trim().slice(0, 64);
    renderClients();
  });

  function segmentedLocal(container, apply) {
    $(container).addEventListener('click', event => {
      const button = event.target.closest('button');
      if (!button) return;
      for (const other of $(container).querySelectorAll('button')) {
        other.setAttribute('aria-pressed', String(other === button));
      }
      apply(button);
      renderClients();
    });
  }
  segmentedLocal('dns-category-filter', button => { clientView.category = button.dataset.category; });
  segmentedLocal('dns-scope-filter', button => { clientView.scope = button.dataset.scope; });

  // ------------------------------------------------------------------ events
  let eventsLoaded = false;
  let eventsController = null;

  async function loadEvents() {
    if (eventsController) eventsController.abort();
    eventsController = new AbortController();
    const container = $('dns-events');
    try {
      const response = await fetch('/api/admin/dns-center/events',
        { cache: 'no-store', signal: eventsController.signal });
      if (!response.ok) throw new Error();
      const payload = await response.json();
      if (!payload.events || !payload.events.length) {
        container.replaceChildren(el('p', 'No DNS state change has been recorded yet. '
          + 'Events appear here the first time a resolver, upstream or filter list '
          + 'actually changes state — none are back-filled.', 'dns-drawer-empty'));
        return;
      }
      container.replaceChildren(...payload.events.map(event => {
        const row = el('div', undefined, 'dns-event severity-'
          + (event.kind === 'resolved' ? 'resolved' : (event.severity || 'info')));
        const head = el('div', undefined, 'dns-event-head');
        head.append(el('strong', event.title || event.event_type || 'DNS event'),
          el('span', event.at ? new Date(event.at).toLocaleString() : '—', 'dns-event-time'));
        row.append(head);
        row.append(el('p', event.detail || ''));
        const meta = el('div', undefined, 'dns-event-meta');
        meta.append(el('span', event.target || '—'));
        if (event.value) meta.append(el('span', String(event.value)));
        row.append(meta);
        return row;
      }));
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      container.replaceChildren(el('p', 'DNS event history unavailable.', 'dns-drawer-empty'));
    }
  }

  // ------------------------------------------------------------------ overview
  function renderOverview(data) {
    const message = $('dns-status');
    if (data.available === false) {
      message.textContent = 'AdGuard Home is not answering on 127.0.0.1:3000 — DNS Center values below are the last known sample.';
      message.classList.add('cc-global-critical');
    } else if (data.available === null || data.available === undefined) {
      message.textContent = data.note || 'DNS collector has not produced a sample yet.';
      message.classList.remove('cc-global-critical');
    } else {
      message.textContent = `${data.health === 'HEALTHY' ? 'DNS OPERATIONAL' : data.health}`
        + ` · collector ${data.collection_age_seconds === null ? 'UNKNOWN' : Math.round(data.collection_age_seconds) + 's ago'}`
        + ` · ${data.freshness}`;
      message.classList.toggle('cc-global-critical', data.health === 'CRITICAL');
    }

    const cache = data.cache || {};
    const upstreams = data.upstreams || null;
    const upstreamState = upstreams === null ? 'UNKNOWN'
      : upstreams.every(u => u.healthy) ? 'HEALTHY'
        : upstreams.some(u => u.healthy) ? 'WARNING' : 'CRITICAL';

    const cluster = data.cluster || {};
    const clusterCards = [card('DNS Cluster', cluster.state || 'UNKNOWN', {
      'Resolvers serving': cluster.serving === null || cluster.serving === undefined ? null : `${cluster.serving} / ${cluster.total}`,
      'Fully healthy': cluster.healthy === null || cluster.healthy === undefined ? null : `${cluster.healthy} / ${cluster.total}`,
      'Redundancy': cluster.redundant === null || cluster.redundant === undefined ? null : cluster.redundant,
      'Last probe': cluster.collection_age_seconds === null || cluster.collection_age_seconds === undefined ? null : Math.round(cluster.collection_age_seconds) + 's ago',
    })];
    clusterCards[0].append(el('p', cluster.note || '', 'dns-note'));
    for (const member of cluster.members || []) {
      const memberCard = card(member.label || member.node, member.health || 'UNKNOWN', {
        'Role': member.role,
        'Address': (member.address || '') + ':53',
        'Answering': member.answering,
        'Filtering': member.filtering,
        'Latency': ms(member.latency_ms),
        'State': member.detail,
      });
      memberCard.classList.add('is-clickable');
      memberCard.tabIndex = 0;
      memberCard.setAttribute('role', 'button');
      memberCard.addEventListener('click', () => resolverDrawer(member));
      memberCard.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); resolverDrawer(member); }
      });
      clusterCards.push(memberCard);
    }
    $('dns-cluster').replaceChildren(...clusterCards);

    $('dns-overview').replaceChildren(
      card('AdGuard Home', data.health || 'UNKNOWN', {
        'Status': data.available === true ? (data.running ? 'RUNNING' : 'NOT RUNNING') : data.available === false ? 'UNAVAILABLE' : 'UNKNOWN',
        'Version': data.version,
        'Filtering': data.protection_enabled,
        'DNSSEC validation': data.dnssec_enabled,
        'DNS server': (data.server_addresses || []).join(' · '),
        'Container restarts': data.container ? data.container.restart_count : null,
      }),
      card('Queries', data.health === 'CRITICAL' ? 'CRITICAL' : 'HEALTHY', {
        ['Queries (last ' + (data.stats_window || 'window') + ')']: data.queries,
        'Blocked': data.blocked,
        'Blocked %': data.blocked_percent === null ? null : data.blocked_percent + '%',
        'Active clients': data.active_clients,
      }),
      card('Performance', upstreamState === 'CRITICAL' ? 'CRITICAL' : 'HEALTHY', {
        'Average processing time': ms(data.avg_processing_ms),
        'Collector API latency': ms(data.api_latency_ms),
        ['Cache hits (last ' + (cache.sample_size || 0) + ' queries)']: cache.hit_percent === null || cache.hit_percent === undefined ? null : cache.hit_percent + '%',
        'Cache size': data.cache_size,
      }),
      card('Upstream health', upstreamState, {
        'Configured upstreams': (data.configured_upstreams || []).join(' · '),
        'Fallback': (data.configured_fallback || []).join(' · '),
        'Last probe': data.upstreams_checked_at ? new Date(data.upstreams_checked_at * 1000).toLocaleString() : null,
        'Freshness': data.freshness,
      }),
      card('Privacy & retention', 'HEALTHY', {
        'Query log': data.querylog_enabled,
        'Query log retention': data.querylog_interval_hours === null || data.querylog_interval_hours === undefined ? null : data.querylog_interval_hours + ' h',
        'Client IP anonymisation': 'OFF (admin-only view)',
        'Public status page': 'Reachability only',
      }),
    );

    renderStrip(data);
    renderAnomalies(data);
    renderKpis(data);
    renderTopology(data);
    traffic.data = data.traffic || null;
    if (active('traffic')) drawTraffic();

    clientView.data = data.top_clients || [];
    renderClients();

    // Same real client list, ranked by what AdGuard actually filtered.
    const share = item => typeof item.count === 'number' && item.count > 0
      && typeof item.blocked === 'number'
      ? Math.round(item.blocked / item.count * 1000) / 10 : null;
    const blockedClients = (data.top_clients || [])
      .filter(item => typeof item.blocked === 'number' && item.blocked > 0)
      .slice()
      .sort((left, right) => right.blocked - left.blocked);
    $('dns-blocked-sample').textContent = data.blocked_sample_size === null
      || data.blocked_sample_size === undefined ? '—' : data.blocked_sample_size;
    rows('dns-top-blocked-clients', blockedClients, item => [
      item.name || 'Unknown client',
      item.key,
      num(count(item.blocked)),
      num(count(item.count)),
      num(percent(share(item))),
    ], (row, item) => clickable(row, () => clientDrawer(item.key, item.name)));

    rows('dns-queried', data.top_queried_domains,
      item => [wrap(item.key), num(count(item.count))],
      (row, item) => clickable(row, () => domainDrawer(item.key)));
    rows('dns-blocked', data.top_blocked_domains,
      item => [wrap(item.key), num(count(item.count))],
      (row, item) => clickable(row, () => domainDrawer(item.key)));

    // AdGuard's own per-upstream mean, when it has served enough traffic to have one.
    const upstreamTiming = new Map((data.top_upstreams_avg_ms || [])
      .map(entry => [entry.key, entry.count]));
    const upstreamVolume = new Map((data.top_upstreams || [])
      .map(entry => [entry.key, entry.count]));
    const upstreamCards = (upstreams || []).map(u => {
      const node = card(u.address, u.healthy ? 'HEALTHY' : 'CRITICAL', {
        'Role': u.role === 'fallback' ? 'fallback (last resort)' : 'upstream',
        'Result': u.healthy ? 'OK' : (u.detail || 'FAILED'),
        'Responses': upstreamVolume.has(u.address) ? upstreamVolume.get(u.address) : null,
        'Average response': upstreamTiming.has(u.address)
          ? upstreamTiming.get(u.address) + ' ms' : null,
        'Last probe': data.upstreams_checked_at
          ? new Date(data.upstreams_checked_at * 1000).toLocaleString() : null,
      });
      // A fallback is visually distinct: it is not a peer of the primaries.
      if (u.role === 'fallback') node.classList.add('is-fallback');
      node.classList.add('is-clickable');
      node.tabIndex = 0;
      node.setAttribute('role', 'button');
      const open = () => upstreamDrawer(u, {
        checkedAt: data.upstreams_checked_at,
        responses: upstreamVolume.get(u.address),
        average: upstreamTiming.get(u.address),
      });
      node.addEventListener('click', open);
      node.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); }
      });
      return node;
    });
    if (!upstreamCards.length) {
      upstreamCards.push(card('Upstreams', 'UNKNOWN', { 'Probe': 'Not completed yet' }));
    }
    $('dns-upstreams').replaceChildren(...upstreamCards);

    // A disabled list is grey and reads DISABLED. Red is reserved for a real error.
    const filterCards = (data.filters || []).map(filter => card(
      filter.name || 'unnamed list', filter.state || 'UNKNOWN', {
        'Status': filter.enabled ? 'enabled' : 'disabled by configuration',
        'Rules': filter.rules,
        'Last updated': filter.updated || null,
        'Update interval': data.filter_update_interval_hours
          ? data.filter_update_interval_hours + ' h' : null,
      }));
    if (!filterCards.length) {
      filterCards.push(card('Filter lists', 'UNKNOWN', { 'Source': 'Not available' }));
    }
    $('dns-filters-cards').replaceChildren(...filterCards);
  }

  // -------------------------------------------------------------- query log
  const state = { filter: 'ALL', limit: 50, client: '', domain: '', type: '',
    cursor: null, appending: false };
  let recentLoaded = false;
  let recentController = null;

  // A resolver failure is an error; NXDOMAIN and friends are legitimate answers and
  // keep their own wording rather than being recoloured as failures.
  const ERROR_STATUS = new Set(['SERVFAIL', 'REFUSED', 'NOTIMP', 'FORMERR']);

  function resultCell(item) {
    const cell = el('td');
    const badge = (text, kind) => {
      const chip = el('span', text, 'dns-badge ' + kind);
      if (item.status) chip.title = 'DNS status: ' + item.status;
      return chip;
    };
    if (item.blocked) cell.append(badge('Blocked', 'blocked'));
    else if (ERROR_STATUS.has(String(item.status || '').toUpperCase())) {
      cell.append(badge(item.status, 'error'));
    } else if (item.status && item.status !== 'NOERROR') {
      cell.append(badge(item.status, 'live'));
    } else {
      cell.append(badge('Allowed', 'allowed'));
    }
    if (item.cached) cell.append(badge('Cached', 'cached'));
    return cell;
  }

  function recentRow(item) {
    const row = el('tr');
    row.append(
      el('td', item.time ? new Date(item.time).toLocaleTimeString() : '—'),
      el('td', item.client_name || item.client || 'Unknown client'),
      wrap(item.name || '—'),
      el('td', item.type || '—'),
      resultCell(item),
      num(item.elapsed_ms === null || item.elapsed_ms === undefined
        ? '—' : String(item.elapsed_ms)),
    );
    clickable(row, () => queryDrawer(item));
    return row;
  }

  function describeFilters(payload) {
    const parts = ['filter ' + payload.filter];
    if (state.client) parts.push('client "' + state.client + '"');
    if (state.domain) parts.push('domain "' + state.domain + '"');
    if (state.type) parts.push('type ' + state.type);
    return parts.join(' · ');
  }

  function renderRecent(payload, append) {
    const body = $('dns-recent').tBodies[0];
    if (append) {
      const first = body.rows[0];
      if (first && first.cells.length === 1) body.replaceChildren();
      for (const item of payload.rows) body.append(recentRow(item));
    } else if (!payload.rows.length) {
      const empty = el('tr');
      const cell = el('td', 'No matching DNS records in the retained query log.');
      cell.colSpan = $('dns-recent').tHead.rows[0].cells.length;
      empty.append(cell);
      body.replaceChildren(empty);
    } else {
      body.replaceChildren(...payload.rows.map(recentRow));
    }
    state.cursor = payload.older_than;
    $('dns-more').disabled = !payload.older_than || !payload.rows.length;
    $('dns-recent-message').textContent = payload.rows.length
      ? `${payload.rows.length} record(s) · ${describeFilters(payload)}`
        + (payload.post_filtered
          ? ` · ${payload.fetched} scanned server-side for a filter AdGuard cannot express,`
            + ' so a short page is not the end of the log'
          : '')
      : 'No matching DNS records in the retained query log.';
  }

  function recentParams(limit) {
    const params = new URLSearchParams({ limit: String(limit), filter: state.filter });
    if (state.client) params.set('client', state.client);
    if (state.domain) params.set('domain', state.domain);
    if (state.type) params.set('type', state.type);
    return params;
  }

  async function loadRecent(append) {
    if (state.appending) return;
    state.appending = true;
    $('dns-more').disabled = true;
    if (recentController) recentController.abort();
    recentController = new AbortController();
    const params = recentParams(state.limit);
    if (append && state.cursor) params.set('older_than', state.cursor);
    try {
      const response = await fetch('/api/admin/dns-center/recent?' + params.toString(),
        { cache: 'no-store', signal: recentController.signal });
      if (response.status === 401) { $('dns-recent-message').textContent = 'Session expired — sign in again.'; return; }
      if (!response.ok) throw new Error();
      renderRecent(await response.json(), append);
    } catch (error) {
      if (!error || error.name !== 'AbortError') {
        $('dns-recent-message').textContent = 'Recent DNS activity unavailable.';
      }
    } finally {
      state.appending = false;
    }
  }

  // ------------------------------------------------------------------- live
  // LIVE keeps at most LIVE_ROWS in the DOM and only polls while the Query Log
  // section is the visible one, the tab is in the foreground and LIVE is on.
  const LIVE_ROWS = 30;
  const LIVE_INTERVAL = 5000;
  const live = { on: false, timer: null, controller: null, busy: false };

  function liveRow(item) {
    const row = el('div', undefined, 'dns-live-row' + (item.blocked ? ' is-blocked' : ''));
    row.append(
      el('span', item.time ? new Date(item.time).toLocaleTimeString() : '—', 'dns-live-time'),
      el('span', item.client_name || item.client || 'Unknown client', 'dns-live-client'),
      el('span', item.name || '—', 'dns-live-domain'),
      el('span', item.blocked ? 'BLOCKED' : (item.status || 'ALLOWED'),
        'dns-badge ' + (item.blocked ? 'blocked' : 'allowed')),
      el('span', item.elapsed_ms === null || item.elapsed_ms === undefined
        ? (item.cached ? 'cached' : '') : item.elapsed_ms + ' ms', 'dns-live-ms'),
    );
    return row;
  }

  function liveContainer() {
    let node = $('dns-live-feed');
    if (!node) {
      node = el('section', undefined, 'panel cc-card dns-live-feed');
      node.id = 'dns-live-feed';
      node.setAttribute('aria-live', 'off');
      $('dns-section-querylog').insertBefore(node, $('dns-section-querylog').lastElementChild);
    }
    return node;
  }

  async function livePoll() {
    if (live.busy || !live.on || !active('querylog') || document.hidden) return;
    live.busy = true;
    if (live.controller) live.controller.abort();
    live.controller = new AbortController();
    try {
      const params = recentParams(25);
      const response = await fetch('/api/admin/dns-center/recent?' + params.toString(),
        { cache: 'no-store', signal: live.controller.signal });
      if (!response.ok) throw new Error();
      const payload = await response.json();
      const container = liveContainer();
      // Replace rather than append: a bounded, capped list can never grow unbounded.
      container.replaceChildren(
        el('p', 'LIVE · newest ' + Math.min(LIVE_ROWS, payload.rows.length)
          + ' queries · refreshed every ' + LIVE_INTERVAL / 1000 + 's', 'dns-note'),
        ...payload.rows.slice(0, LIVE_ROWS).map(liveRow));
    } catch (error) {
      if (!error || error.name !== 'AbortError') {
        liveContainer().replaceChildren(el('p', 'Live feed unavailable.', 'dns-drawer-empty'));
      }
    } finally {
      live.busy = false;
    }
  }

  function syncLive() {
    const shouldRun = live.on && active('querylog') && !document.hidden;
    if (shouldRun && live.timer === null) {
      live.timer = window.setInterval(livePoll, LIVE_INTERVAL);
      livePoll();
    } else if (!shouldRun && live.timer !== null) {
      window.clearInterval(live.timer);
      live.timer = null;
      if (live.controller) { live.controller.abort(); live.controller = null; }
    }
    if (!live.on) {
      const node = $('dns-live-feed');
      if (node) node.remove();
    }
  }

  $('dns-live').addEventListener('click', () => {
    live.on = !live.on;
    $('dns-live').setAttribute('aria-pressed', String(live.on));
    $('dns-live').classList.toggle('is-on', live.on);
    syncLive();
  });

  // ------------------------------------------------------------------ refresh
  let busy = false;
  let summaryController = null;
  async function refresh() {
    if (busy || view.hidden || document.hidden) return;
    busy = true;
    if (summaryController) summaryController.abort();
    summaryController = new AbortController();
    try {
      const response = await fetch('/api/admin/dns-center',
        { cache: 'no-store', signal: summaryController.signal });
      if (response.status === 401) { $('dns-status').textContent = 'Session expired — sign in again.'; return; }
      if (!response.ok) throw new Error();
      renderOverview(await response.json());
    } catch (error) {
      if (!error || error.name !== 'AbortError') {
        $('dns-status').textContent = 'UNKNOWN · DNS Center connection lost; displayed values are last known / STALE';
        $('dns-status').classList.add('cc-global-critical');
      }
    } finally {
      busy = false;
    }
  }

  function segmented(container, key, cast) {
    $(container).addEventListener('click', event => {
      const button = event.target.closest('button');
      if (!button) return;
      for (const other of $(container).querySelectorAll('button')) {
        other.setAttribute('aria-pressed', String(other === button));
      }
      state[key] = cast(button.dataset[key]);
      state.cursor = null;
      loadRecent(false);
    });
  }
  segmented('dns-filters', 'filter', String);
  segmented('dns-limits', 'limit', Number);

  // The traffic range only reslices data already in memory — no request, no refetch.
  $('dns-traffic-ranges').addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button) return;
    for (const other of $('dns-traffic-ranges').querySelectorAll('button')) {
      other.setAttribute('aria-pressed', String(other === button));
    }
    traffic.buckets = Number(button.dataset.range);
    drawTraffic();
  });

  const canvas = $('dns-traffic-canvas');
  canvas.addEventListener('mousemove', showTip);
  canvas.addEventListener('mouseleave', hideTip);
  canvas.addEventListener('touchstart', event => {
    if (event.touches && event.touches.length === 1) showTip(event.touches[0]);
  }, { passive: true });
  canvas.addEventListener('touchend', hideTip, { passive: true });

  // Canvas has no intrinsic layout, so a resize needs one redraw. Debounced, and
  // skipped entirely unless the traffic section is the visible one.
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    if (!active('traffic')) return;
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(drawTraffic, 180);
  });

  function applyQueryFilters() {
    state.client = $('dns-client-input').value.trim().slice(0, 64);
    state.domain = $('dns-domain-input').value.trim().toLowerCase().slice(0, 253);
    state.type = $('dns-type-input').value;
    state.cursor = null;
    loadRecent(false);
    if (live.on) livePoll();
  }
  $('dns-client-apply').addEventListener('click', applyQueryFilters);
  for (const id of ['dns-client-input', 'dns-domain-input']) {
    $(id).addEventListener('keydown', event => {
      if (event.key === 'Enter') { event.preventDefault(); applyQueryFilters(); }
    });
  }
  $('dns-type-input').addEventListener('change', applyQueryFilters);
  $('dns-client-clear').addEventListener('click', () => {
    $('dns-client-input').value = '';
    $('dns-domain-input').value = '';
    $('dns-type-input').value = '';
    state.client = state.domain = state.type = '';
    state.cursor = null;
    loadRecent(false);
  });
  $('dns-more').addEventListener('click', () => loadRecent(true));

  function open() {
    if (view.hidden) return;
    refresh();
    if (section === 'querylog' && !recentLoaded) { recentLoaded = true; loadRecent(false); }
    if (section === 'overview' && !eventsLoaded) { eventsLoaded = true; loadEvents(); }
    syncLive();
  }
  // The DNS view is only refreshed while it is the visible view; it never polls in
  // the background, so the query log is not fetched unless an admin is looking at it.
  for (const button of document.querySelectorAll('[data-view="dns"],[data-open-view="dns"]')) {
    button.addEventListener('click', () => setTimeout(open, 0));
  }
  window.setInterval(() => { if (!document.hidden) open(); }, 30000);
  document.addEventListener('visibilitychange', () => {
    syncLive();
    if (!document.hidden) open();
  });
  // Restore the sub-section the hash asked for before the first paint.
  showSection((location.hash.split('/')[1] || 'overview'));
  setTimeout(open, 0);
})();
