// Wire buttons so we can pass the clicked element into checkIP()
document.getElementById('check_abuseipdb').addEventListener('click', (e) => {
  checkIP('/check_ip/', e.currentTarget);
});
document.getElementById('check_abuseipdb').addEventListener('click', (e) => {
  sendStatistic('/send_ip_statistics/');
});
document.getElementById('check_virustotal').addEventListener('click', (e) => {
  checkIP('/check_ip_virustotal/', e.currentTarget);
});
document.getElementById('check_virustotal').addEventListener('click', (e) => {
  sendStatistic('/send_ip_vt_statistics/');
});
document.getElementById('check_url_virustotal').addEventListener('click', (e) => {
  checkIP('/check_url_virustotal/', e.currentTarget);
});
document.getElementById('check_url_virustotal').addEventListener('click', (e) => {
  sendStatistic('/send_url_statistics/');
});
document.getElementById('check_domain_virustotal').addEventListener('click', (e) => {
  checkIP('/check_domain_virustotal/', e.currentTarget);
});
document.getElementById('check_domain_virustotal').addEventListener('click', (e) => {
  sendStatistic('/send_domain_statistics/');
});
document.getElementById('check_user_agent').addEventListener('click', (e) => {
  checkIP('/check_user_agent/', e.currentTarget);
});
document.getElementById('check_user_agent').addEventListener('click', (e) => {
  sendStatistic('/send_user_agent_statistics/');
});
document.getElementById('check_hash_virustotal').addEventListener('click', (e) => {
  checkIP('/check_hash_virustotal/', e.currentTarget);
});
document.getElementById('check_hash_virustotal').addEventListener('click', (e) => {
  sendStatistic('/send_hash_statistics/');
});

const resultsDiv = document.getElementById('results_table');

function showLoading(message = 'Fetching results…') {
  // Only show spinner; do NOT disable all buttons.
  resultsDiv.innerHTML = `
    <table class="results">
      <tbody>
        <tr>
          <td>
            <div class="spinner" role="status" aria-live="polite" aria-label="${message}"></div>
            <span>${message}</span>
          </td>
        </tr>
      </tbody>
    </table>`;
}

function getCSRFToken() {
  const el = document.querySelector('input[name=csrfmiddlewaretoken]');
  if (el) return el.value;
  const m = document.cookie.match(/(^|;\s*)csrftoken=([^;]+)/);
  return m ? decodeURIComponent(m[2]) : '';
}

function showError(msg) {
  resultsDiv.innerHTML = `<div>Error: ${msg}</div>`;
}

async function sendStatistic(url) {
  const ipData = document.getElementById('ip_input').value;
  const csrfToken = getCSRFToken();
  
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRFToken': csrfToken,
      },
      body: new URLSearchParams({ ip_data: ipData }),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `HTTP ${res.status} ${res.statusText}`);
    }
  } catch (err) {
    if (err.name !== 'AbortError') showError(err.message);
  }
}


async function checkIP(url, buttonEl) {
  const ipData = document.getElementById('ip_input').value;
  const csrfToken = getCSRFToken();

  // Disable only the clicked button
  buttonEl.disabled = true;
  buttonEl.setAttribute('aria-busy', 'true');

  showLoading('Retrieving data…');

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRFToken': csrfToken,
      },
      body: new URLSearchParams({ ip_data: ipData }),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `HTTP ${res.status} ${res.statusText}`);
    }

    const data = await res.json();
    displayResults(data);
  } catch (err) {
    if (err.name !== 'AbortError') showError(err.message);
  } finally {
    // Re-enable only the clicked button
    buttonEl.disabled = false;
    buttonEl.removeAttribute('aria-busy');
  }
}

function displayResults(data) {
  resultsDiv.innerHTML = ''; // Clear previous results
  if (data && data.results) {
    const table = document.createElement('table');
    table.border = '1';
    const headerRow = table.insertRow(0);
    const headerCell = headerRow.insertCell(0);
    headerCell.innerHTML = '<b>Results</b>';
    data.results.forEach((result) => {
      const row = table.insertRow();
      const cell = row.insertCell();
      cell.textContent = result;
    });
    resultsDiv.appendChild(table);
  } else {
    resultsDiv.textContent = 'No results found.';
  }
}

// ===== Leaderboard (static section) =====
const lbEntity = document.getElementById('lb_entity');
const lbPeriod = document.getElementById('lb_period');
const leaderboardDiv = document.getElementById('leaderboard_results');
let leaderboardAbort = null;
let leaderboardTimer = null;

function showLeaderboardLoading(msg = 'Loading leaderboard…') {
  leaderboardDiv.innerHTML = `
    <table class="results"><tbody><tr><td>
      <div class="spinner" role="status" aria-live="polite" aria-label="${msg}"></div>
      <span>${msg}</span>
    </td></tr></tbody></table>`;
}

function renderLeaderboard(rows) {
  if (!rows || rows.length === 0) {
    leaderboardDiv.innerHTML = `<div class="leaderboard-empty">No data for the selected period.</div>`;
    return;
  }
  const tbl = document.createElement('table');
  tbl.className = 'results';

  const thead = tbl.createTHead();
  const hr = thead.insertRow();
  ['#', 'Value', 'Count'].forEach(h => {
    const th = document.createElement('th');
    th.textContent = h;
    hr.appendChild(th);
  });

  const tbody = tbl.createTBody();
  rows.forEach((r, i) => {
    const tr = tbody.insertRow();
    tr.insertCell().textContent = i + 1;
    tr.insertCell().textContent = r.value;
    tr.insertCell().textContent = r.count;
  });

  leaderboardDiv.innerHTML = '';
  leaderboardDiv.appendChild(tbl);
}

async function fetchLeaderboard() {
  if (!lbEntity || !lbPeriod) return;
  const entity = lbEntity.value;
  const period = lbPeriod.value;

  // cancel previous fetch if still in flight
  if (leaderboardAbort) leaderboardAbort.abort();
  leaderboardAbort = new AbortController();

  showLeaderboardLoading();
  try {
    const res = await fetch(`/leaderboard/?entity=${encodeURIComponent(entity)}&period=${encodeURIComponent(period)}&limit=10`, {
      signal: leaderboardAbort.signal,
      credentials: 'same-origin'
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    const data = await res.json();
    renderLeaderboard(data.results || []);
  } catch (e) {
    if (e.name !== 'AbortError') {
      leaderboardDiv.innerHTML = `<div class="error-box">Failed to load leaderboard: ${e.message || e}</div>`;
    }
  }
}

function scheduleLeaderboardAutoRefresh() {
  if (leaderboardTimer) clearInterval(leaderboardTimer);
  leaderboardTimer = setInterval(fetchLeaderboard, 5 * 60 * 1000); // every 5 minutes
}

// init on first load
if (lbEntity && lbPeriod && leaderboardDiv) {
  lbEntity.addEventListener('change', () => { fetchLeaderboard(); scheduleLeaderboardAutoRefresh(); });
  lbPeriod.addEventListener('change', () => { fetchLeaderboard(); scheduleLeaderboardAutoRefresh(); });

  // First paint
  fetchLeaderboard();
  scheduleLeaderboardAutoRefresh();

  // Optional: pause refresh in background tabs; refresh immediately when returning
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (leaderboardTimer) clearInterval(leaderboardTimer);
    } else {
      fetchLeaderboard();
      scheduleLeaderboardAutoRefresh();
    }
  });
}
