/** IGA-Guard 3.0 六页大屏共享导航与 API 工具 */
window.IGA_PAGES = [
  { id: 'hub', href: '/static/hub.html', label: '总览' },
  { id: 'p1', href: '/static/p1_monitor.html', label: 'P1 监控' },
  { id: 'p2', href: '/static/p2_detail.html', label: 'P2 详情' },
  { id: 'p3', href: '/static/p3_localization.html', label: 'P3 定位' },
  { id: 'p4', href: '/static/p4_risk.html', label: 'P4 风险' },
  { id: 'p5', href: '/static/p5_evolution.html', label: 'P5 演化' },
  { id: 'p6', href: '/static/p6_rules.html', label: 'P6 规则' },
  { id: 'dash', href: '/static/dashboard.html', label: '综合大屏' },
];

window.igaPct = function (v) {
  return v == null ? '-' : (v * 100).toFixed(2) + '%';
};

window.igaMountShell = function (activeId, subtitle) {
  const nav = document.getElementById('iga-nav');
  if (nav) {
    nav.innerHTML = window.IGA_PAGES.map(
      (p) =>
        `<a href="${p.href}" class="${p.id === activeId ? 'active' : ''}">${p.label}</a>`
    ).join('');
  }
  const sub = document.getElementById('iga-subtitle');
  if (sub && subtitle) sub.textContent = subtitle;
};

window.igaFetchHealth = async function (vm) {
  try {
    const d = await fetch('/api/health').then((r) => r.json());
    if (vm) {
      vm.health = d.status;
      vm.version = d.version || '3.0.0';
    }
    return d;
  } catch (_) {
    if (vm) vm.health = 'offline';
    return null;
  }
};

window.igaRefreshCore = async function (vm) {
  const [a, s, l, e, m] = await Promise.all([
    fetch('/api/alerts').then((r) => r.json()),
    fetch('/api/stats').then((r) => r.json()),
    fetch('/api/metrics/latency').then((r) => r.json()),
    fetch('/api/evolution/history').then((r) => r.json()),
    fetch('/api/metrics/overall').then((r) => r.json()),
  ]);
  if (vm.alerts !== undefined) vm.alerts = a.alerts || [];
  if (vm.stats !== undefined) vm.stats = s;
  if (vm.latency !== undefined) vm.latency = l;
  if (vm.evoHistory !== undefined) vm.evoHistory = e.history || [];
  if (vm.overallMetrics !== undefined && m && m.obfuscated_attack_recall != null) {
    vm.overallMetrics = m;
  }
  return { alerts: a, stats: s, latency: l, evolution: e, overall: m };
};
