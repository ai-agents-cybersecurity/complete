(() => {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // Elements
  const elHealth = $('#healthScore');
  const elResp = $('#mRespTime');
  const elErr = $('#mErrorRate');
  const elAcc = $('#mAccuracy');
  const elDrift = $('#mDrift');
  const elCpu = $('#mCpu');
  const elAlertCount = $('#alertCount');
  const elStatus = $('#statusMsg');
  const elLast = $('#lastUpdated');

  const elModelInput = $('#modelIdInput');
  const elHoursInput = $('#hoursInput');
  const btnLoad = $('#loadBtn');
  const btnRefresh = $('#refreshBtn');
  const autoRefresh = $('#autoRefreshSwitch');

  let charts = { resp: null, acc: null, drift: null };
  let currentModel = window.INIT_MODEL_ID || 'demo-model';

  function setStatus(msg) {
    elStatus.textContent = msg;
  }

  function setLastUpdated(d) {
    elLast.textContent = `Updated: ${new Date(d).toLocaleString()}`;
  }

  async function getJSON(url, opts) {
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return await res.json();
  }

  function fmt(n, digits = 2) {
    if (n === null || n === undefined || Number.isNaN(Number(n))) return '--';
    return Number(n).toFixed(digits);
  }

  function upsertChart(key, ctx, labels, data, color) {
    if (!charts[key]) {
      charts[key] = new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            label: key,
            data,
            borderColor: color,
            backgroundColor: color + '33',
            pointRadius: 0,
            tension: 0.25,
            fill: true
          }]
        },
        options: {
          responsive: true,
          animation: false,
          scales: {
            x: { type: 'category', display: true, ticks: { maxTicksLimit: 8 } },
            y: { beginAtZero: false }
          },
          plugins: { legend: { display: false } }
        }
      });
    } else {
      const ch = charts[key];
      ch.data.labels = labels;
      ch.data.datasets[0].data = data;
      ch.update();
    }
  }

  function updateCards(dash) {
    elHealth.textContent = Math.round(dash.health_score);
    const m = dash.current_metrics || {};
    elResp.textContent = fmt(m.response_time_ms, 0);
    elErr.textContent = fmt(m.error_rate_percent, 2);
    elAcc.textContent = fmt(m.accuracy_score, 3);
    elDrift.textContent = fmt(m.drift_score, 3);
    elCpu.textContent = fmt(m.cpu_utilization_percent, 1);
    elAlertCount.textContent = dash.alert_count ?? '--';
    setLastUpdated(dash.last_updated || Date.now());
  }

  function updateCharts(trends) {
    const labels = (trends.timestamps || []).map(ts => ts.replace('T', ' ').slice(5,16));
    upsertChart('resp', $('#respChart'), labels, trends.response_time || [], '#4f46e5');
    upsertChart('acc', $('#accChart'), labels, trends.accuracy || [], '#16a34a');
    upsertChart('drift', $('#driftChart'), labels, trends.drift || [], '#f59e0b');
  }

  function renderAlerts(alerts) {
    const tbody = $('#alertsTable tbody');
    tbody.innerHTML = '';
    alerts.forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${a.id}</td>
        <td>${a.timestamp?.replace('T',' ') ?? ''}</td>
        <td>${a.alert_type}</td>
        <td>${a.metric_name}</td>
        <td>${fmt(a.current_value, 3)}</td>
        <td>${fmt(a.threshold_value, 3)}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span></td>
        <td><button class="btn btn-small" data-ack="${a.id}">Ack</button></td>`;
      tbody.appendChild(tr);
    });

    $$('#alertsTable [data-ack]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-ack');
        try {
          await getJSON(`/api/alerts/ack/${id}`, { method: 'POST' });
          setStatus(`Alert ${id} acknowledged`);
          await refresh();
        } catch (e) {
          setStatus(`Ack failed: ${e.message}`);
        }
      });
    });
  }

  async function loadDashboard(modelId, hours) {
    setStatus('Loading dashboard...');
    const dash = await getJSON(`/api/dashboard/${encodeURIComponent(modelId)}?hours=${hours}`);
    if (dash.error) throw new Error(dash.error);
    updateCards(dash);
    updateCharts(dash.trends || {});
    setStatus('Dashboard loaded');
  }

  async function loadAlerts(modelId, hours) {
    setStatus('Loading alerts...');
    const a = await getJSON(`/api/alerts/${encodeURIComponent(modelId)}?hours=${hours}`);
    renderAlerts(a.alerts || []);
    setStatus('Alerts loaded');
  }

  async function refresh() {
    const modelId = elModelInput.value.trim() || 'demo-model';
    const hours = Number(elHoursInput.value) || 6;
    currentModel = modelId;
    try {
      await loadDashboard(modelId, hours);
      await loadAlerts(modelId, hours);
    } catch (e) {
      setStatus(`Error: ${e.message}`);
    }
  }

  function bindControls() {
    btnLoad.addEventListener('click', refresh);
    btnRefresh.addEventListener('click', refresh);
    elModelInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') refresh();
    });
    elHoursInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') refresh();
    });

    let timer = setInterval(() => { if (autoRefresh.checked) refresh(); }, 15000);
    autoRefresh.addEventListener('change', () => {
      if (!autoRefresh.checked) setStatus('Auto-refresh paused');
      else setStatus('Auto-refresh enabled');
    });
    // safety: refresh interval reset on visibility change
    document.addEventListener('visibilitychange', () => {
      clearInterval(timer);
      timer = setInterval(() => { if (autoRefresh.checked && !document.hidden) refresh(); }, 15000);
    });
  }

  document.addEventListener('DOMContentLoaded', async () => {
    elModelInput.value = currentModel;
    bindControls();
    await refresh();
  });
})();
