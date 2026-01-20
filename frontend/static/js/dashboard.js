// === Variables & State ===
const packetsTableBody = document.querySelector('#packetsTable tbody');
const statTotal = document.getElementById('statTotal');
const statIp = document.getElementById('statIp');
const statTcp = document.getElementById('statTcp');
const statAlerts = document.getElementById('statAlerts');
const alertsList = document.getElementById('alertsList');
const detailBox = document.getElementById('detailBox');

let running = false;
let simInterval = null;
let chartInterval = null;
let stats = { total: 0, ip: 0, tcp: 0, alerts: 0 };
let suspiciousSet = new Set();
let watchFlags = new Set(['SYN']);
let selectedPacket = null; // Stores currently clicked packet

// === Chart.js Initialization ===
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Total Packets',
            borderColor: '#fbbf24',
            backgroundColor: 'rgba(251, 191, 36, 0.1)',
            data: [],
            tension: 0.4,
            fill: true,
            pointRadius: 0
        }, {
            label: 'Alerts',
            borderColor: '#ef4444',
            data: [],
            tension: 0.4,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
            x: { display: false },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
        },
        plugins: { legend: { labels: { color: '#9aa6b2' } } }
    }
});

// === Helper Functions ===
function randomIPv4() {
  return [10, Math.floor(Math.random()*256), Math.floor(Math.random()*256), Math.floor(Math.random()*256)].join('.');
}

function makeRandomPacket() {
  const proto = Math.random() < 0.6 ? 'TCP' : 'IP';
  const src = randomIPv4();
  const dst = '192.168.1.' + (1 + Math.floor(Math.random() * 200));
  const srcPort = 1024 + Math.floor(Math.random() * 50000);
  const dstPort = [80, 443, 22, 23, 25, 3389][Math.floor(Math.random() * 6)];
  const len = 20 + Math.floor(Math.random() * 1400);
  const flags = [];
  if (proto === 'TCP') {
    if (Math.random() < 0.3) flags.push('SYN');
    if (Math.random() < 0.4) flags.push('ACK');
  }
  return { time: new Date().toLocaleTimeString(), src, dst, proto, srcPort, dstPort, flags: flags.join(','), len };
}

function addAlert(text, level = 'warn') {
  stats.alerts++;
  statAlerts.textContent = stats.alerts;
  const it = document.createElement('div');
  it.className = `alertItem ${level}`;
  it.innerHTML = `<strong>${level.toUpperCase()}</strong> <span style="color:#ccc">${new Date().toLocaleTimeString()}</span><br/>${text}`;
  alertsList.prepend(it);
  if (alertsList.children.length > 50) alertsList.removeChild(alertsList.lastChild);
}

function addPacketToTable(pkt) {
  // Filtering
  const filterIp = document.getElementById('filterIp').checked;
  const filterTcp = document.getElementById('filterTcp').checked;
  if (pkt.proto === 'TCP' && !filterTcp) return;
  if (pkt.proto === 'IP' && !filterIp) return;

  stats.total++;
  statTotal.textContent = stats.total;
  if (pkt.proto === 'IP') { stats.ip++; statIp.textContent = stats.ip; }
  if (pkt.proto === 'TCP') { stats.tcp++; statTcp.textContent = stats.tcp; }

  // Logic check
  let level = null;
  if (suspiciousSet.has(pkt.src) || suspiciousSet.has(pkt.dst)) {
    level = 'alert';
    addAlert(`Suspicious IP: ${pkt.src} → ${pkt.dst}`, 'alert');
  } else if (pkt.flags) {
    pkt.flags.split(',').forEach(f => {
      if (watchFlags.has(f.trim())) {
        level = 'warn';
        addAlert(`Flag ${f} from ${pkt.src}`, 'warn');
      }
    });
  }

  // Render Row
  const tr = document.createElement('tr');
  if (level) tr.classList.add(level);
  tr.innerHTML = `
    <td>${pkt.time}</td>
    <td>${pkt.src}</td>
    <td>${pkt.dst}</td>
    <td>${pkt.proto}</td>
    <td>${pkt.srcPort}</td>
    <td>${pkt.dstPort}</td>
    <td>${pkt.flags}</td>
    <td>${pkt.len}</td>
  `;

  // Click Event (Selection)
  tr.addEventListener('click', () => {
    selectedPacket = pkt;
    detailBox.textContent = JSON.stringify(pkt, null, 2);
    document.querySelectorAll('tbody tr.selected').forEach(r => r.classList.remove('selected'));
    tr.classList.add('selected');
  });

  packetsTableBody.prepend(tr);
  if (packetsTableBody.children.length > 200) packetsTableBody.removeChild(packetsTableBody.lastChild);
}

function updateChart() {
    const now = new Date().toLocaleTimeString();
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(stats.total);
    trafficChart.data.datasets[1].data.push(stats.alerts);

    if (trafficChart.data.labels.length > 20) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
        trafficChart.data.datasets[1].data.shift();
    }
    trafficChart.update();
}

// === Controls ===
function startSim() {
  if (running) return;
  running = true;
  document.getElementById('startBtn').disabled = true;
  document.getElementById('stopBtn').disabled = false;
  
  // Packet Loop
  const rate = Number(document.getElementById('rateInput').value) || 6;
  simInterval = setInterval(() => {
    addPacketToTable(makeRandomPacket());
  }, 1000 / rate);
  
  // Chart Loop (1s tick)
  chartInterval = setInterval(updateChart, 760);
}

function stopSim() {
  running = false;
  clearInterval(simInterval);
  clearInterval(chartInterval);
  document.getElementById('startBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
}

function clearAll() {
    packetsTableBody.innerHTML = '';
    alertsList.innerHTML = '';
    stats = { total: 0, ip: 0, tcp: 0, alerts: 0 };
    statTotal.textContent = 0; statIp.textContent = 0; statTcp.textContent = 0; statAlerts.textContent = 0;
    trafficChart.data.labels = [];
    trafficChart.data.datasets.forEach(d => d.data = []);
    trafficChart.update();
}

function exportCsv() {
    const rows = [];
    rows.push(['Time', 'Src', 'Dst', 'Proto', 'SrcPort', 'DstPort', 'Flags', 'Len'].join(','));
    for (const tr of packetsTableBody.children) {
      const cols = Array.from(tr.children).map(td => `"${td.textContent.replace(/"/g, '""')}"`);
      rows.push(cols.join(','));
    }
    const csv = rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'ids_packets.csv'; a.click();
    URL.revokeObjectURL(url);
}

// === Admin Tools Listeners ===
document.getElementById('btnWhois').addEventListener('click', () => {
    if (!selectedPacket) return alert("Select a packet first!");
    window.open(`https://who.is/whois-ip/ip-address/${selectedPacket.src}`, '_blank');
});

document.getElementById('btnTrace').addEventListener('click', () => {
    if (!selectedPacket) return alert("Select a packet first!");
    alert(`Simulating Traceroute to ${selectedPacket.src}...\n\n1  192.168.1.1 (0.4ms)\n2  10.0.0.1 (1.2ms)\n3  ${selectedPacket.src} (14ms)`);
});

document.getElementById('btnBan').addEventListener('click', () => {
    if (!selectedPacket) return alert("Select a packet first!");
    const input = document.getElementById('suspiciousInput');
    input.value = input.value ? input.value + `, ${selectedPacket.src}` : selectedPacket.src;
    
    // Update set
    const raw = input.value;
    suspiciousSet.clear();
    raw.split(',').map(s=>s.trim()).filter(Boolean).forEach(ip => suspiciousSet.add(ip));
    
    addAlert(`ADMIN ACTION: Blocked IP ${selectedPacket.src}`, 'alert');
});

document.getElementById('startBtn').addEventListener('click', startSim);
document.getElementById('stopBtn').addEventListener('click', stopSim);
document.getElementById('clearBtn').addEventListener('click', clearAll);
document.getElementById('exportBtn').addEventListener('click', exportCsv);

// Initial setup
document.getElementById('stopBtn').disabled = true;

// Parse inputs initially
const rawSusp = document.getElementById('suspiciousInput').value;
if(rawSusp) rawSusp.split(',').forEach(ip => suspiciousSet.add(ip.trim()));