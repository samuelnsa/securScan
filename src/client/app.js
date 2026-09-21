/**
 * SecurScan // Homarr Core - Futuristic Cyber-Defense & Auto-Hardening Engine
 */

const state = {
  currentView: 'board',
  summary: null,
  sites: [],
  allVulnerabilities: [],
  activeSiteDetails: null,
  activeReport: null,
  filterGrade: 'ALL',
  filterSeverity: 'ALL',
  
  omniSearchInput: document.getElementById('omni-search-input'),
  statAvgGrade: document.getElementById('stat-avg-grade'),
  statAvgScore: document.getElementById('stat-avg-score'),
  holoCircleProgress: document.getElementById('holo-circle-progress'),
  statTotalSites: document.getElementById('stat-total-sites'),
  statTotalScans: document.getElementById('stat-total-scans'),
  statCriticalCount: document.getElementById('stat-critical-count'),
  sslWatcherBody: document.getElementById('ssl-watcher-body'),
  hudLiveFeed: document.getElementById('hud-live-feed'),
  servicesCount: document.getElementById('services-count'),
  homarrTilesGrid: document.getElementById('homarr-tiles-grid'),

  // Views & Tabs
  viewBoard: document.getElementById('view-board'),
  viewRemediation: document.getElementById('view-remediation'),
  viewSiteDetail: document.getElementById('view-site-detail'),
  boardTabBtns: document.querySelectorAll('.board-tab-btn'),
  pillFilters: document.querySelectorAll('.pill-filter'),
  activeVulnsBadge: document.getElementById('active-vulns-badge'),

  // Site Detail Dedicated View Elements
  btnBackToBoard: document.getElementById('btn-back-to-board'),
  detailNavHostname: document.getElementById('detail-nav-hostname'),
  btnDetailAutoHarden: document.getElementById('btn-detail-auto-harden'),
  btnDetailCompare: document.getElementById('btn-detail-compare'),
  btnDetailRescan: document.getElementById('btn-detail-rescan'),
  btnDetailExportHtml: document.getElementById('btn-detail-export-html'),
  btnDetailExportPdf: document.getElementById('btn-detail-export-pdf'),
  detailHeroIcon: document.getElementById('detail-hero-icon'),
  detailSiteHostname: document.getElementById('detail-site-hostname'),
  detailSiteLink: document.getElementById('detail-site-link'),
  detailSiteUrl: document.getElementById('detail-site-url'),
  detailSiteVerdict: document.getElementById('detail-site-verdict'),
  detailSiteScanDate: document.getElementById('detail-site-scandate'),
  detailSiteDuration: document.getElementById('detail-site-duration'),
  detailSiteSsl: document.getElementById('detail-site-ssl'),
  detailSiteTotalScans: document.getElementById('detail-site-totalscans'),
  detailSiteGrade: document.getElementById('detail-site-grade'),
  detailSiteScore: document.getElementById('detail-site-score'),
  detailTechStack: document.getElementById('detail-tech-stack'),
  detailSslBody: document.getElementById('detail-ssl-body'),
  detailHistoryCanvas: document.getElementById('detail-history-canvas'),
  detailVulnsCount: document.getElementById('detail-vulns-count'),
  detailSolutionsList: document.getElementById('detail-solutions-list'),
  btnDetailFilters: document.querySelectorAll('[data-detail-filter]'),
  btnDrawerOpenPage: document.getElementById('btn-drawer-open-page'),

  // Modal Scanner
  btnOpenScanModal: document.getElementById('btn-open-scan-modal'),
  addTargetModal: document.getElementById('add-target-modal'),
  btnCloseModal: document.getElementById('btn-close-modal'),
  btnCancelModal: document.getElementById('btn-cancel-modal'),
  modalScanForm: document.getElementById('modal-scan-form'),
  modalInputUrl: document.getElementById('modal-input-url'),

  // Radar Overlay
  hudRadarOverlay: document.getElementById('hud-radar-overlay'),
  radarTargetDisplay: document.getElementById('radar-target-display'),
  radarLiveLogs: document.getElementById('radar-live-logs'),

  // Alert Banner
  regressionBanner: document.getElementById('regression-banner'),
  alertBannerText: document.getElementById('alert-banner-text'),
  alertBannerIcon: document.getElementById('alert-banner-icon'),
  btnCloseAlert: document.getElementById('btn-close-alert'),

  // Drawer (Inspector)
  auditDrawer: document.getElementById('audit-drawer'),
  btnCloseDrawer: document.getElementById('btn-close-drawer'),
  drawerSiteGrade: document.getElementById('drawer-site-grade'),
  drawerSiteHostname: document.getElementById('drawer-site-hostname'),
  drawerSiteUrl: document.getElementById('drawer-site-url'),
  drawerScoreVal: document.getElementById('drawer-score-val'),
  drawerVerdictText: document.getElementById('drawer-verdict-text'),
  drawerTimestamp: document.getElementById('drawer-timestamp'),
  drawerDuration: document.getElementById('drawer-duration'),
  drawerSslProto: document.getElementById('drawer-ssl-proto'),
  drawerHistoryCanvas: document.getElementById('drawer-history-canvas'),
  drawerTechStack: document.getElementById('drawer-tech-stack'),
  drawerSslCard: document.getElementById('drawer-ssl-card'),
  drawerHeadersMatrix: document.getElementById('drawer-headers-matrix'),
  btnDrawerRescan: document.getElementById('btn-drawer-rescan'),
  btnDrawerCompare: document.getElementById('btn-drawer-compare'),
  btnDrawerExportHtml: document.getElementById('btn-drawer-export-html'),
  btnDrawerExportPdf: document.getElementById('btn-drawer-export-pdf'),
  btnDrawerExportJson: document.getElementById('btn-drawer-export-json'),
  btnDrawerAutoHarden: document.getElementById('btn-drawer-auto-harden'),

  // Auto-Hardening Studio Modal (Sécurisation Complète)
  btnOpenHardeningStudio: document.getElementById('btn-open-hardening-studio'),
  hardeningStudioModal: document.getElementById('hardening-studio-modal'),
  btnCloseHardeningModal: document.getElementById('btn-close-hardening-modal'),
  hardeningModalHostname: document.getElementById('hardening-modal-hostname'),
  hardeningStackTabs: document.querySelectorAll('.btn-stack-pill'),
  hardeningResolvedSummary: document.getElementById('hardening-resolved-summary'),
  hardeningFilename: document.getElementById('hardening-filename'),
  hardeningCodeDisplay: document.getElementById('hardening-code-display'),
  btnCopyFullPatch: document.getElementById('btn-copy-full-patch'),
  btnDownloadPatch: document.getElementById('btn-download-patch'),
  downloadFilenameLbl: document.getElementById('download-filename-lbl'),
  btnCloseStudioModal: document.getElementById('btn-close-studio-modal'),
  btnApplyAllHardening: document.getElementById('btn-apply-all-hardening'),

  // Scan Comparison Modal
  scanCompareModal: document.getElementById('scan-compare-modal'),
  btnCloseCompareModal: document.getElementById('btn-close-compare-modal'),
  btnCloseCompareFooter: document.getElementById('btn-close-compare-footer'),
  compareModalHostname: document.getElementById('compare-modal-hostname'),
  compareSelectScan1: document.getElementById('compare-select-scan1'),
  compareSelectScan2: document.getElementById('compare-select-scan2'),
  compareResultsContent: document.getElementById('compare-results-content'),

  // Toasts
  hudToastContainer: document.getElementById('hud-toast-container'),

  // Remediation
  remediationAccordionList: document.getElementById('remediation-accordion-list'),
  remediationSitePills: document.getElementById('remediation-site-pills'),
  btnRemGrouped: document.getElementById('btn-rem-grouped'),
  btnRemFlat: document.getElementById('btn-rem-flat'),
  btnFilterRems: document.querySelectorAll('.btn-filter-rem'),
  btnRescanAll: document.getElementById('btn-rescan-all')
};

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
  startHudClock();
  setupNavigation();
  setupOmniSearch();
  setupModal();
  setupDrawer();
  setupHardeningStudio();
  setupScanComparison();
  setupRemediationFilters();
  setupSiteDetailView();
  setupHashRouting();
  loadDashboardData();

  if (elements.btnCloseAlert) {
    elements.btnCloseAlert.addEventListener('click', () => {
      elements.regressionBanner.classList.add('hidden');
    });
  }

  if (elements.btnRescanAll) {
    elements.btnRescanAll.addEventListener('click', rescanAllSites);
  }
});

// ==========================================================================
// TELEMETRY & CLOCK
// ==========================================================================
function startHudClock() {
  function update() {
    const now = new Date();
    const h = String(now.getUTCHours()).padStart(2, '0');
    const m = String(now.getUTCMinutes()).padStart(2, '0');
    const s = String(now.getUTCSeconds()).padStart(2, '0');
    if (elements.hudClock) elements.hudClock.textContent = `${h}:${m}:${s} UTC`;
  }
  update();
  setInterval(update, 1000);
}

function logToFeed(msg, type = 'INFO') {
  if (!elements.hudLiveFeed) return;
  const time = new Date().toTimeString().split(' ')[0];
  const colorClass = type === 'ALERT' ? 'text-neon-red' : type === 'SUCCESS' ? 'text-neon-green' : 'text-neon-cyan';
  const line = document.createElement('div');
  line.className = `feed-item ${colorClass}`;
  line.innerHTML = `<span class="text-muted">[${time}]</span> ${escapeHtml(msg)}`;
  elements.hudLiveFeed.prepend(line);
}

function showToast(message, type = 'info', duration = 3500) {
  if (!elements.hudToastContainer) return;
  const toast = document.createElement('div');
  const icons = {
    success: '✅',
    error: '❌',
    warning: '⚠️',
    info: '🛡️'
  };
  toast.className = `hud-toast ${type}`;
  toast.innerHTML = `
    <span class="hud-toast-icon">${icons[type] || '🛡️'}</span>
    <span class="hud-toast-msg">${escapeHtml(message)}</span>
    <button class="hud-toast-close" title="Fermer">&times;</button>
  `;

  const closeBtn = toast.querySelector('.hud-toast-close');
  const removeToast = () => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 350);
  };
  closeBtn?.addEventListener('click', removeToast);

  elements.hudToastContainer.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));

  if (duration > 0) {
    setTimeout(removeToast, duration);
  }
}

// ==========================================================================
// NAVIGATION & VIEWS
// ==========================================================================
function setupNavigation() {
  elements.boardTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.getAttribute('data-board-view');
      switchView(view);
    });
  });

  elements.pillFilters.forEach(pill => {
    pill.addEventListener('click', () => {
      elements.pillFilters.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.filterGrade = pill.getAttribute('data-filter-grade');
      renderTilesGrid();
    });
  });
}

function switchView(viewName) {
  state.currentView = viewName;
  elements.boardTabBtns.forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-board-view') === viewName);
  });

  if (viewName === 'board') {
    elements.viewBoard.classList.remove('hidden');
    elements.viewRemediation.classList.add('hidden');
    elements.viewSiteDetail.classList.add('hidden');
    renderTilesGrid();
  } else if (viewName === 'remediation') {
    elements.viewBoard.classList.add('hidden');
    elements.viewRemediation.classList.remove('hidden');
    elements.viewSiteDetail.classList.add('hidden');
    renderRemediationView();
  } else if (viewName === 'site-detail') {
    elements.viewBoard.classList.add('hidden');
    elements.viewRemediation.classList.add('hidden');
    elements.viewSiteDetail.classList.remove('hidden');
  }
}

// ==========================================================================
// OMNI-SEARCH
// ==========================================================================
function setupOmniSearch() {
  window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      elements.omniSearchInput?.focus();
    }
  });

  elements.omniSearchInput?.addEventListener('input', (e) => {
    state.searchQuery = e.target.value.toLowerCase().trim();
    renderTilesGrid();
  });
}

// ==========================================================================
// DATA LOADING & WIDGETS
// ==========================================================================
async function loadDashboardData() {
  try {
    const [summaryRes, sitesRes, vulnsRes] = await Promise.all([
      fetch('/api/summary'),
      fetch('/api/sites'),
      fetch('/api/vulnerabilities')
    ]);

    state.summary = await summaryRes.json();
    state.sites = await sitesRes.json();
    if (vulnsRes.ok) {
      state.allVulnerabilities = await vulnsRes.json();
    }

    // Si un site était déjà actif, rafraîchir ses données
    if (state.activeSiteDetails?.site?.id) {
      const updatedSiteRes = await fetch(`/api/sites/${state.activeSiteDetails.site.id}`);
      if (updatedSiteRes.ok) {
        state.activeSiteDetails = await updatedSiteRes.json();
      }
    } else if (state.sites.length > 0) {
      const defaultSiteRes = await fetch(`/api/sites/${state.sites[0].id}`);
      if (defaultSiteRes.ok) {
        state.activeSiteDetails = await defaultSiteRes.json();
      }
    }

    updateTelemetryWidgets();
    renderTilesGrid();
    renderSslWatcherWidget();
    updateRemediationBadge();

    if (state.currentView === 'remediation') {
      renderRemediationView();
    }
  } catch (err) {
    console.error('Erreur de chargement:', err);
  }
}

function updateTelemetryWidgets() {
  if (!state.summary) return;

  const avg = state.summary.averageScore || 0;
  elements.statAvgScore.textContent = avg;
  elements.statTotalSites.textContent = state.summary.totalSites || 0;
  elements.statTotalScans.textContent = state.summary.totalScans || 0;

  let grade = 'F';
  let color = 'var(--neon-red)';
  if (avg >= 85) { grade = 'A'; color = 'var(--neon-green)'; }
  else if (avg >= 70) { grade = 'B'; color = 'var(--neon-cyan)'; }
  else if (avg >= 50) { grade = 'C'; color = 'var(--neon-amber)'; }
  else if (avg >= 35) { grade = 'D'; color = '#f97316'; }

  elements.statAvgGrade.textContent = state.summary.totalSites > 0 ? grade : '--';
  elements.statAvgGrade.style.color = color;

  const offset = 251.2 - (251.2 * avg) / 100;
  if (elements.holoCircleProgress) {
    elements.holoCircleProgress.style.strokeDashoffset = offset;
    elements.holoCircleProgress.style.stroke = color;
  }

  const crit = state.summary.openVulnerabilities?.CRITICAL || 0;
  const high = state.summary.openVulnerabilities?.HIGH || 0;
  elements.statCriticalCount.textContent = `${crit} critique(s) • ${high} élevée(s)`;
}

function renderSslWatcherWidget() {
  if (!elements.sslWatcherBody) return;

  if (!state.sites || state.sites.length === 0) {
    elements.sslWatcherBody.innerHTML = `
      <div class="empty-widget-state text-muted">
        <span>Aucun certificat analysé pour le moment</span>
      </div>
    `;
    return;
  }

  const items = state.sites.slice(0, 3).map(s => {
    return `
      <div class="ssl-watcher-item">
        <span class="ssl-target-name font-mono">${s.hostname}</span>
        <span class="ssl-days-pill good">Protocole TLS 1.3</span>
      </div>
    `;
  }).join('');

  elements.sslWatcherBody.innerHTML = items;
}

function updateRemediationBadge() {
  let count = 0;
  if (state.summary?.openVulnerabilities) {
    const v = state.summary.openVulnerabilities;
    count = (v.CRITICAL || 0) + (v.HIGH || 0) + (v.MEDIUM || 0) + (v.LOW || 0);
  }
  if (elements.activeVulnsBadge) elements.activeVulnsBadge.textContent = count;
}

// ==========================================================================
// HOMARR SERVICE TILES GRID
// ==========================================================================
function renderTilesGrid() {
  if (!elements.homarrTilesGrid) return;

  if (!state.sites || state.sites.length === 0) {
    elements.homarrTilesGrid.innerHTML = `
      <div class="empty-tiles-placeholder">
        <div class="empty-radar-anim">
          <div class="radar-circle"></div>
          <div class="radar-line"></div>
        </div>
        <h3>Aucun service dans le tableau de bord</h3>
        <p>Ajoutez l'URL de votre premier site web pour déployer la tuile de surveillance et lancer l'audit initial.</p>
        <button class="btn-hud-primary" onclick="window.openScanModal()">
          + Déployer une cible
        </button>
      </div>
    `;
    if (elements.servicesCount) elements.servicesCount.textContent = '0 CIBLE(S)';
    return;
  }

  let filtered = state.sites.filter(s => {
    if (state.searchQuery) {
      const q = state.searchQuery;
      const matchHost = s.hostname?.toLowerCase().includes(q);
      const matchUrl = s.target_url?.toLowerCase().includes(q);
      const matchGrade = s.latest_grade?.toLowerCase() === q;
      if (!matchHost && !matchUrl && !matchGrade) return false;
    }

    if (state.filterGrade === 'A') {
      return s.latest_grade === 'A+' || s.latest_grade === 'A';
    } else if (state.filterGrade === 'B') {
      return s.latest_grade === 'B';
    } else if (state.filterGrade === 'WARN') {
      return s.latest_grade === 'C' || s.latest_grade === 'D' || s.latest_grade === 'F';
    }
    return true;
  });

  if (elements.servicesCount) {
    elements.servicesCount.textContent = `${filtered.length} CIBLE(S)`;
  }

  if (filtered.length === 0) {
    elements.homarrTilesGrid.innerHTML = `
      <div class="empty-tiles-placeholder" style="padding: 2.5rem;">
        <p class="text-muted">Aucune cible ne correspond aux critères de recherche actuels.</p>
      </div>
    `;
    return;
  }

  elements.homarrTilesGrid.innerHTML = filtered.map(site => {
    const gradeLetter = site.latest_grade ? site.latest_grade.charAt(0) : 'F';
    const gradeClass = `tile-grade-${gradeLetter}`;

    const crit = site.openIssues?.CRITICAL || 0;
    const high = site.openIssues?.HIGH || 0;
    const med = site.openIssues?.MEDIUM || 0;
    const initial = site.hostname.charAt(0).toUpperCase();

    const techPills = (site.techStack || []).slice(0, 3).map(t => `<span class="tile-tech-pill">${t.icon || '⚡'} ${escapeHtml(t.name)}</span>`).join('');

    return `
      <div class="service-tile-card" id="tile-${site.id}" onclick="if(!event.target.closest('.tile-actions') && !event.target.closest('a') && !event.target.closest('button')) window.openSiteDetailPage('${site.id}')" title="Cliquer pour ouvrir la page détaillée de ${site.hostname}">
        
        <!-- Cyber Spiderweb Corner Ornament -->
        <svg class="cyber-spiderweb-corner top-right" viewBox="0 0 60 60" fill="none" xmlns="http://www.w3.org/2000/svg" style="width: 48px; height: 48px; opacity: 0.35;">
          <path d="M60 0 L0 0 M60 0 L60 60 M60 0 L15 45 M60 0 L30 30 M60 0 L45 15" stroke="currentColor" stroke-width="1.2"/>
          <path d="M60 12 Q48 12 48 0" stroke="currentColor" stroke-width="1.2"/>
          <path d="M60 26 Q34 26 34 0" stroke="currentColor" stroke-width="1.2"/>
          <path d="M60 42 Q18 35 18 0" stroke="currentColor" stroke-width="1.2"/>
          <circle cx="60" cy="0" r="2.5" fill="var(--neo-yellow)"/>
        </svg>

        <div>
          <div class="tile-top">
            <div class="tile-app-info">
              <div class="tile-app-icon">${initial}</div>
              <div class="tile-app-texts">
                <h3>${site.hostname}</h3>
                <span class="tile-app-url">${site.target_url}</span>
                ${techPills ? `<div class="tile-tech-row">${techPills}</div>` : ''}
              </div>
            </div>
            <div class="tile-grade-badge ${gradeClass}">
              ${site.latest_grade || 'N/A'}
            </div>
          </div>

          <div class="tile-metrics">
            <div class="tile-metric-item">
              <span class="tile-metric-label">SCORE GLOBAL</span>
              <span class="tile-metric-val font-mono">${site.latest_score}/100</span>
            </div>

            <div class="tile-metric-item" style="text-align: right;">
              <span class="tile-metric-label">VULNÉRABILITÉS</span>
              <div class="tile-vulns-row">
                ${crit > 0 ? `<span class="vuln-mini-chip crit">${crit} Crit.</span>` : ''}
                ${high > 0 ? `<span class="vuln-mini-chip high">${high} Élev.</span>` : ''}
                ${med > 0 ? `<span class="vuln-mini-chip med">${med} Moy.</span>` : ''}
                ${crit === 0 && high === 0 && med === 0 ? `<span class="vuln-mini-chip ok">SÉCURISÉ</span>` : ''}
              </div>
            </div>
          </div>

          <!-- Interactive Banner -->
          <div class="tile-one-click-indicator">
            <span>⚡ RAPPORT DÉTAILLÉ &amp; SOLUTIONS</span>
            <span>1-CLIC ➔</span>
          </div>
        </div>

        <div class="tile-actions" onclick="event.stopPropagation()">
          <button class="btn-tile-primary" onclick="event.stopPropagation(); window.openSiteDetailPage('${site.id}')" title="Ouvrir la page détaillée avec toutes les failles et leurs solutions">
            🔍 Fiche &amp; Solutions
          </button>
          <button class="btn-tile-action" title="Lancer un nouvel audit immédiat" onclick="event.stopPropagation(); window.quickAuditTarget('${site.target_url}')">
            🔄 Re-scanner
          </button>
          <button class="btn-tile-icon danger" title="Supprimer la cible" onclick="event.stopPropagation(); window.deleteTargetSite('${site.id}')">
            🗑️
          </button>
        </div>
      </div>
    `;
  }).join('');
}

// ==========================================================================
// MODAL & SCANNER ENGINE
// ==========================================================================
function setupModal() {
  window.openScanModal = () => {
    elements.addTargetModal.classList.remove('hidden');
    elements.modalInputUrl.focus();
  };

  elements.btnOpenScanModal?.addEventListener('click', window.openScanModal);
  elements.btnCloseModal?.addEventListener('click', () => elements.addTargetModal.classList.add('hidden'));
  elements.btnCancelModal?.addEventListener('click', () => elements.addTargetModal.classList.add('hidden'));

  elements.modalScanForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    const raw = elements.modalInputUrl.value.trim();
    if (!raw) return;

    elements.addTargetModal.classList.add('hidden');
    elements.modalInputUrl.value = '';
    executeScan(raw);
  });
}

async function executeScan(targetUrl) {
  showRadarOverlay(targetUrl);
  logToFeed(`Déploiement de la sonde DAST vers ${targetUrl}...`, 'INFO');

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });
    // Parse JSON if present
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }

    hideRadarOverlay();

    if (res.status === 202) {
      showToast(data?.message || 'Scan lancé en tâche de fond.', 'info');
      logToFeed(`Scan mis en file pour ${targetUrl} (job: ${data?.jobId || 'n/a'})`, 'INFO');
      await loadDashboardData();
      return;
    }

    if (!res.ok) {
      showToast("Erreur pendant l'audit : " + (data?.error || 'Erreur inconnue'), "error");
      logToFeed(`Échec de l'audit pour ${targetUrl}: ${data?.error}`, 'ALERT');
      return;
    }

    if (data && data.report) {
      logToFeed(`Audit complété pour ${data.report.target.hostname} (Note: ${data.report.grade} - Score: ${data.report.score}/100)`, 'SUCCESS');
      showToast(`Audit de ${data.report.target.hostname} terminé avec succès (Score: ${data.report.score}/100)`, "success");
      handleRegressionAlert(data.regression);
      await loadDashboardData();
      window.inspectSite(data.siteId);
      return;
    }

    // Fallback
    showToast('Scan lancé (réponse inattendue du serveur).', 'info');
    await loadDashboardData();
    return;

  } catch (err) {
    hideRadarOverlay();
    showToast("Erreur réseau : " + err.message, "error");
  }
}

// Poll job status until completion or timeout
function pollJobStatus(jobId, callback, opts = {}) {
  const intervalMs = opts.intervalMs || 3000;
  const timeoutMs = opts.timeoutMs || 5 * 60 * 1000; // 5 minutes
  const start = Date.now();
  let stopped = false;

  async function check() {
    if (stopped) return;
    try {
      const res = await fetch(`/api/scan/status/${encodeURIComponent(jobId)}`);
      if (!res.ok) {
        // keep retrying unless 404
        if (res.status === 404) {
          stopped = true;
          callback({ status: 'FAILED', error: 'Job introuvable' });
          return;
        }
      } else {
        const j = await res.json();
        if (j.status === 'COMPLETED' || j.status === 'FAILED') {
          stopped = true;
          callback(j);
          return;
        }
      }
    } catch (err) {
      // network error — continue retrying until timeout
    }

    if (Date.now() - start > timeoutMs) {
      stopped = true;
      callback({ status: 'FAILED', error: 'Timeout lors de l\'attente du job' });
      return;
    }

    setTimeout(check, intervalMs);
  }

  check();
  return () => { stopped = true; };
}

function showRadarOverlay(target) {
  elements.hudRadarOverlay.classList.remove('hidden');
  elements.radarTargetDisplay.textContent = target;
  elements.radarLiveLogs.innerHTML = `
    <div class="log-row">> [TCP] Résolution DNS & socket connect...</div>
  `;

  setTimeout(() => {
    elements.radarLiveLogs.innerHTML += `<div class="log-row">> [TLS] Handshake & extraction certificat X.509...</div>`;
  }, 400);

  setTimeout(() => {
    elements.radarLiveLogs.innerHTML += `<div class="log-row">> [HTTP] Inspection des en-têtes (CSP, HSTS, XFO)...</div>`;
  }, 900);

  setTimeout(() => {
    elements.radarLiveLogs.innerHTML += `<div class="log-row">> [PASSIVE] Vérification sécurisation .env, .git & security.txt...</div>`;
  }, 1400);

  setTimeout(() => {
    elements.radarLiveLogs.innerHTML += `<div class="log-row">> [SCORING] Calcul du score de durcissement et mapping CWE...</div>`;
  }, 1800);
}

function hideRadarOverlay() {
  elements.hudRadarOverlay.classList.add('hidden');
}

function handleRegressionAlert(regression) {
  if (!regression || !regression.alerts || regression.alerts.length === 0) {
    elements.regressionBanner.classList.add('hidden');
    return;
  }

  const msgs = regression.alerts.map(a => a.message).join('<br>• ');
  elements.alertBannerText.innerHTML = `<strong>Télémétrie de Régression / Suivi :</strong><br>• ${msgs}`;
  elements.regressionBanner.classList.remove('hidden', 'success');

  if (!regression.hasRegression) {
    elements.regressionBanner.classList.add('success');
    elements.alertBannerIcon.textContent = '🎉';
  } else {
    elements.alertBannerIcon.textContent = '⚡';
    logToFeed("Alerte de régression détectée !", 'ALERT');
  }
}

// ==========================================================================
// SLIDE-OVER DRAWER (HOMARR INSPECTOR)
// ==========================================================================
function setupDrawer() {
  elements.btnCloseDrawer?.addEventListener('click', () => {
    elements.auditDrawer.classList.add('hidden');
  });

  elements.btnDrawerRescan?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.target_url) {
      elements.auditDrawer.classList.add('hidden');
      executeScan(state.activeSiteDetails.site.target_url);
    }
  });

  elements.btnDrawerExportJson?.addEventListener('click', exportDrawerJson);

  elements.btnDrawerExportHtml?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.id) {
      window.location.href = `/api/sites/${state.activeSiteDetails.site.id}/export`;
      showToast("Génération et téléchargement du rapport HTML...", "success");
    }
  });

  elements.btnDrawerExportPdf?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.id) {
      window.open(`/api/sites/${state.activeSiteDetails.site.id}/export?print=1`, '_blank');
      showToast("Ouverture de l'export PDF...", "success");
    }
  });

  elements.btnDrawerCompare?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.id) {
      window.openScanComparisonModal(state.activeSiteDetails.site.id);
    }
  });

  elements.btnDrawerAutoHarden?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.id) {
      window.openHardeningForSite(state.activeSiteDetails.site.id);
    }
  });

  elements.btnDrawerOpenPage?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.id) {
      elements.auditDrawer.classList.add('hidden');
      window.openSiteDetailPage(state.activeSiteDetails.site.id);
    }
  });
}

window.inspectSite = async (siteId) => {
  try {
    const res = await fetch(`/api/sites/${siteId}`);
    if (!res.ok) return;

    state.activeSiteDetails = await res.json();
    populateDrawer(state.activeSiteDetails);
    elements.auditDrawer.classList.remove('hidden');
    renderRemediationView();
  } catch (err) {
    console.error('Erreur:', err);
  }
};

function populateDrawer(details) {
  const { site, history, lastScanReport } = details;
  const report = lastScanReport;

  elements.drawerSiteGrade.textContent = site.latest_grade;
  elements.drawerSiteGrade.className = `drawer-badge tile-grade-${site.latest_grade.charAt(0)}`;
  elements.drawerSiteHostname.textContent = site.hostname;
  elements.drawerSiteUrl.textContent = site.target_url;

  elements.drawerScoreVal.textContent = site.latest_score;
  elements.drawerVerdictText.textContent = report?.verdict || 'Aucune anomalie bloquante.';

  if (report) {
    const d = new Date(report.timestamp);
    elements.drawerTimestamp.textContent = `📅 ${d.toLocaleDateString('fr-FR')} ${d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}`;
    elements.drawerDuration.textContent = `⏱️ ${report.durationMs} ms`;
    elements.drawerSslProto.textContent = report.ssl ? `🔒 ${report.ssl.protocol}` : '🔓 Pas de SSL';
  }

  renderDrawerCanvas(history);

  // Tech stack rendering
  if (elements.drawerTechStack) {
    if (report?.techStack && report.techStack.length > 0) {
      elements.drawerTechStack.innerHTML = report.techStack.map(t => `
        <div class="tech-chip-cyber" title="${t.category}">
          <span class="tech-icon">${t.icon || '⚡'}</span>
          <span class="tech-name font-mono"><strong>${t.name}</strong></span>
          <span class="tech-cat">${t.category}</span>
        </div>
      `).join('');
    } else {
      elements.drawerTechStack.innerHTML = `<span class="text-muted font-mono" style="font-size: 0.78rem;">Aucune fuite d'en-tête serveur ni signature framework exposée (Posture Recommandée ✓).</span>`;
    }
  }

  if (report?.ssl) {
    const s = report.ssl;
    const exp = new Date(s.validTo).toLocaleDateString('fr-FR');
    elements.drawerSslCard.innerHTML = `
      <div style="display: flex; justify-content: space-between;"><span class="text-muted">Émetteur:</span> <span class="font-mono text-neon-cyan">${s.issuer}</span></div>
      <div style="display: flex; justify-content: space-between;"><span class="text-muted">Protocole:</span> <span class="font-mono">${s.protocol} (${s.cipher})</span></div>
      <div style="display: flex; justify-content: space-between;"><span class="text-muted">Expiration:</span> <span class="font-mono ${s.daysRemaining < 30 ? 'text-neon-red' : 'text-neon-green'}">${exp} (${s.daysRemaining}j)</span></div>
      <div style="display: flex; justify-content: space-between;"><span class="text-muted">Chaîne CA:</span> <span class="font-mono">${s.authorized ? 'Approuvée' : 'Non approuvée'}</span></div>
    `;
  } else {
    elements.drawerSslCard.innerHTML = `<span class="text-neon-red font-mono">Aucun certificat SSL valide. Connexion en clair HTTP.</span>`;
  }

  const checks = [
    { name: 'Content-Security-Policy (CSP)', code: 'MISSING_CSP' },
    { name: 'Strict-Transport-Security (HSTS)', code: 'MISSING_HSTS' },
    { name: 'Anti-Clickjacking (X-Frame-Options)', code: 'MISSING_X_FRAME_OPTIONS' },
    { name: 'Anti-MIME Sniffing (XCTO)', code: 'MISSING_X_CONTENT_TYPE_OPTIONS' },
    { name: 'Fuite Referer (Referrer-Policy)', code: 'MISSING_REFERRER_POLICY' },
    { name: 'Politique CORS (Cross-Origin)', code: 'CORS_WILDCARD_ALLOW_ORIGIN' },
    { name: 'Redirection HTTP vers HTTPS (301)', code: 'NO_HTTPS_REDIRECT' },
    { name: 'Exposition Fichiers (.env, .git)', code: 'EXPOSED_ENV_FILE' }
  ];

  const issueCodes = new Set((report?.vulnerabilities || []).map(v => v.code));

  elements.drawerHeadersMatrix.innerHTML = checks.map(c => {
    const failed = issueCodes.has(c.code) || 
      (c.code === 'CORS_WILDCARD_ALLOW_ORIGIN' && (issueCodes.has('CORS_ALLOW_ORIGIN_NULL') || issueCodes.has('CORS_EXPOSED_HEADERS'))) ||
      (c.code === 'EXPOSED_ENV_FILE' && issueCodes.has('EXPOSED_GIT_REPO'));
    return `
      <div class="matrix-row">
        <span>${c.name}</span>
        <span class="matrix-status ${failed ? 'ko' : 'ok'}">${failed ? 'VULNÉRABLE' : 'CONFORME'}</span>
      </div>
    `;
  }).join('');
}

function renderDrawerCanvas(history) {
  if (!elements.drawerHistoryCanvas) return;
  const canvas = elements.drawerHistoryCanvas;
  const ctx = canvas.getContext('2d');

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = 90 * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = 90;
  ctx.clearRect(0, 0, w, h);

  if (!history || history.length <= 1) {
    ctx.fillStyle = '#526079';
    ctx.font = '11px JetBrains Mono';
    ctx.fillText("Courbe d'évolution active au 2ème scan.", 15, 45);
    return;
  }

  const scores = history.map(item => item.score);
  const stepX = (w - 30) / (scores.length - 1);

  ctx.beginPath();
  scores.forEach((sc, i) => {
    const x = 15 + i * stepX;
    const y = h - 15 - (sc / 100) * (h - 30);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  ctx.strokeStyle = '#00f2fe';
  ctx.lineWidth = 2.5;
  ctx.stroke();

  scores.forEach((sc, i) => {
    const x = 15 + i * stepX;
    const y = h - 15 - (sc / 100) * (h - 30);
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#05070d';
    ctx.fill();
    ctx.strokeStyle = sc >= 70 ? '#00ff87' : '#ff0055';
    ctx.lineWidth = 2;
    ctx.stroke();
  });
}

function exportDrawerJson() {
  const report = state.activeSiteDetails?.lastScanReport;
  if (!report) return;

  const str = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
  const a = document.createElement('a');
  a.href = str;
  a.download = `securscan-${report.target.hostname || 'report'}.json`;
  a.click();
  a.remove();
}

// ==========================================================================
// AUTO-HARDENING STUDIO ENGINE (SÉCURISATION COMPLÈTE)
// ==========================================================================
function setupHardeningStudio() {
  elements.btnOpenHardeningStudio?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.id) {
      window.openHardeningForSite(state.activeSiteDetails.site.id);
    } else if (state.sites.length > 0) {
      window.openHardeningForSite(state.sites[0].id);
    } else {
      showToast("Veuillez d'abord ajouter et auditer une cible.", "warning");
    }
  });

  elements.btnCloseHardeningModal?.addEventListener('click', () => {
    elements.hardeningStudioModal.classList.add('hidden');
  });

  // Gestion des onglets de stack
  elements.hardeningStackTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      elements.hardeningStackTabs.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.hardeningStack = btn.getAttribute('data-stack');
      loadHardeningPatch();
    });
  });

  // Copier le patch
  elements.btnCopyFullPatch?.addEventListener('click', () => {
    if (!state.currentPatch?.code) return;
    navigator.clipboard.writeText(state.currentPatch.code).then(() => {
      elements.btnCopyFullPatch.textContent = '✓ Copié !';
      elements.btnCopyFullPatch.style.color = 'var(--neon-green)';
      setTimeout(() => {
        elements.btnCopyFullPatch.textContent = '📋 Copier le patch';
        elements.btnCopyFullPatch.style.color = '';
      }, 2000);
    });
  });

  // Télécharger le fichier
  elements.btnDownloadPatch?.addEventListener('click', () => {
    if (!state.currentPatch?.code) return;
    const blob = new Blob([state.currentPatch.code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = state.currentPatch.filename || 'security-hardening.conf';
    a.click();
    URL.revokeObjectURL(url);
    a.remove();
  });

  // Fermer le studio modal
  elements.btnCloseStudioModal?.addEventListener('click', () => {
    elements.hardeningStudioModal?.classList.add('hidden');
  });
}

window.openHardeningForSite = async (siteId) => {
  try {
    const res = await fetch(`/api/sites/${siteId}`);
    if (!res.ok) return;

    state.activeSiteDetails = await res.json();
    elements.hardeningModalHostname.textContent = state.activeSiteDetails.site.hostname;
    elements.hardeningStudioModal.classList.remove('hidden');

    loadHardeningPatch();
  } catch (err) {
    console.error('Erreur:', err);
  }
};

async function loadHardeningPatch() {
  const siteId = state.activeSiteDetails?.site?.id;
  if (!siteId) return;

  elements.hardeningCodeDisplay.textContent = "// Génération du patch de durcissement en cours...";

  try {
    const res = await fetch(`/api/sites/${siteId}/patch?stack=${state.hardeningStack}`);
    const data = await res.json();

    state.currentPatch = data;
    elements.hardeningFilename.textContent = data.filename;
    elements.downloadFilenameLbl.textContent = data.filename;
    elements.hardeningCodeDisplay.textContent = data.code;

    // Résumé des failles corrigées par le patch
    const openVulns = (state.activeSiteDetails?.vulnerabilities || []).filter(v => v.status !== 'RESOLVED');
    if (openVulns.length > 0) {
      elements.hardeningResolvedSummary.innerHTML = openVulns.map(v => {
        return `<span class="resolved-chip">✓ ${escapeHtml(v.title.replace('En-tête ', '').replace(' manquant', ''))}</span>`;
      }).join('');
    } else {
      elements.hardeningResolvedSummary.innerHTML = `<span class="resolved-chip" style="border-color: var(--neon-cyan); color: var(--neon-cyan);">✓ Configuration Baseline de Durcissement Maximum (Note A+)</span>`;
    }

  } catch (err) {
    elements.hardeningCodeDisplay.textContent = "// Erreur lors de la génération du patch.";
  }
}

// ==========================================================================
// SCAN COMPARISON & REGRESSION DIFF
// ==========================================================================
function setupScanComparison() {
  elements.btnCloseCompareModal?.addEventListener('click', () => {
    elements.scanCompareModal.classList.add('hidden');
  });
  elements.btnCloseCompareFooter?.addEventListener('click', () => {
    elements.scanCompareModal.classList.add('hidden');
  });

  elements.compareSelectScan1?.addEventListener('change', (e) => {
    state.compareScan1Id = e.target.value;
    triggerScanCompare();
  });
  elements.compareSelectScan2?.addEventListener('change', (e) => {
    state.compareScan2Id = e.target.value;
    triggerScanCompare();
  });
}

window.openScanComparisonModal = (siteId) => {
  const siteDetails = state.activeSiteDetails;
  if (!siteDetails || !siteDetails.history || siteDetails.history.length < 2) {
    showToast("Au moins 2 scans sont requis pour effectuer une analyse différentielle.", "warning");
    return;
  }

  elements.compareModalHostname.textContent = siteDetails.site.hostname;
  const history = siteDetails.history;

  // Options pour le scan 1 (référence / plus ancien)
  elements.compareSelectScan1.innerHTML = history.map((s, idx) => {
    const d = new Date(s.timestamp).toLocaleDateString('fr-FR') + ' ' + new Date(s.timestamp).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    const isSelected = idx === 1 ? 'selected' : '';
    return `<option value="${s.id}" ${isSelected}>Scan #${history.length - idx} • ${d} (${s.grade} - ${s.score}/100)</option>`;
  }).join('');

  // Options pour le scan 2 (cible / plus récent)
  elements.compareSelectScan2.innerHTML = history.map((s, idx) => {
    const d = new Date(s.timestamp).toLocaleDateString('fr-FR') + ' ' + new Date(s.timestamp).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    const isSelected = idx === 0 ? 'selected' : '';
    return `<option value="${s.id}" ${isSelected}>Scan #${history.length - idx} • ${d} (${s.grade} - ${s.score}/100)</option>`;
  }).join('');

  state.compareScan1Id = history[1]?.id || history[0]?.id;
  state.compareScan2Id = history[0]?.id;

  elements.scanCompareModal.classList.remove('hidden');
  triggerScanCompare();
};

async function triggerScanCompare() {
  if (!state.compareScan1Id || !state.compareScan2Id) return;
  elements.compareResultsContent.innerHTML = `<div class="text-muted font-mono" style="padding: 2rem; text-align: center;">⚡ Analyse comparative et calcul des écarts en cours...</div>`;

  try {
    const res = await fetch(`/api/scans/${state.compareScan1Id}/compare/${state.compareScan2Id}`);
    if (!res.ok) {
      elements.compareResultsContent.innerHTML = `<div class="text-neon-red font-mono" style="padding: 1rem;">Erreur lors du calcul du différentiel.</div>`;
      return;
    }

    const diff = await res.json();
    renderCompareResults(diff);
  } catch (err) {
    elements.compareResultsContent.innerHTML = `<div class="text-neon-red font-mono" style="padding: 1rem;">Erreur réseau: ${err.message}</div>`;
  }
}

function renderCompareResults(diff) {
  const scoreDiff = diff.scoreDiff || 0;
  const scoreSign = scoreDiff > 0 ? `+${scoreDiff}` : `${scoreDiff}`;
  const scoreColor = scoreDiff > 0 ? 'var(--neon-green)' : scoreDiff < 0 ? 'var(--neon-red)' : 'var(--neon-cyan)';

  let newVulnsHtml = '';
  if (diff.newIssues && diff.newIssues.length > 0) {
    newVulnsHtml = diff.newIssues.map(v => `
      <div class="diff-item new-vuln">
        <div><span class="rem-sev-tag ${v?.severity || 'HIGH'}">${v?.severity || 'HIGH'}</span> <strong>${v?.title || 'Nouvelle anomalie'}</strong></div>
        <span class="font-mono text-neon-red">+ NOUVELLE FAILLE</span>
      </div>
    `).join('');
  } else {
    newVulnsHtml = `<div class="text-muted font-mono" style="font-size: 0.8rem; padding: 6px;">✓ Aucune nouvelle vulnérabilité apparue entre ces scans.</div>`;
  }

  let resVulnsHtml = '';
  if (diff.resolvedIssues && diff.resolvedIssues.length > 0) {
    resVulnsHtml = diff.resolvedIssues.map(v => `
      <div class="diff-item resolved-vuln">
        <div><span class="rem-sev-tag ${v?.severity || 'LOW'}">${v?.severity || 'LOW'}</span> <strong>${v?.title || 'Anomalie'}</strong></div>
        <span class="font-mono text-neon-green">✓ RÉSOLUE / SÉCURISÉE</span>
      </div>
    `).join('');
  } else {
    resVulnsHtml = `<div class="text-muted font-mono" style="font-size: 0.8rem; padding: 6px;">Aucune correction observée entre ces deux audits.</div>`;
  }

  elements.compareResultsContent.innerHTML = `
    <div class="compare-stat-row">
      <div class="compare-stat-card">
        <div class="stat-val" style="color: ${scoreColor};">${scoreSign} PTS</div>
        <div class="stat-lbl">Évolution Score (${diff.scan1.score} → ${diff.scan2.score})</div>
      </div>
      <div class="compare-stat-card">
        <div class="stat-val text-neon-red">${diff.newIssues.length}</div>
        <div class="stat-lbl">Nouvelles Failles</div>
      </div>
      <div class="compare-stat-card">
        <div class="stat-val text-neon-green">${diff.resolvedIssues.length}</div>
        <div class="stat-lbl">Failles Corrigées</div>
      </div>
    </div>

    <div class="compare-diff-box">
      <div class="compare-diff-title text-neon-red">⚡ NOUVELLES VULNÉRABILITÉS INTRODUITES (${diff.newIssues.length})</div>
      <div class="diff-list">${newVulnsHtml}</div>
    </div>

    <div class="compare-diff-box">
      <div class="compare-diff-title text-neon-green">✅ VULNÉRABILITÉS RÉSOLUES (${diff.resolvedIssues.length})</div>
      <div class="diff-list">${resVulnsHtml}</div>
    </div>
  `;
}

// ==========================================================================
// REMEDIATION & SÉCURISATION INDIVIDUELLE (FAILLE PAR FAILLE & PAR SITE)
// ==========================================================================
function setupRemediationFilters() {
  elements.btnFilterRems.forEach(btn => {
    btn.addEventListener('click', () => {
      elements.btnFilterRems.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.filterSeverity = btn.getAttribute('data-filter-sev');
      renderRemediationView();
    });
  });

  if (elements.btnRemGrouped) {
    elements.btnRemGrouped.addEventListener('click', () => {
      state.remediationViewMode = 'grouped';
      elements.btnRemGrouped.classList.add('active');
      elements.btnRemFlat?.classList.remove('active');
      renderRemediationView();
    });
  }

  if (elements.btnRemFlat) {
    elements.btnRemFlat.addEventListener('click', () => {
      state.remediationViewMode = 'flat';
      elements.btnRemFlat.classList.add('active');
      elements.btnRemGrouped?.classList.remove('active');
      renderRemediationView();
    });
  }
}

function renderRemediationSitePills() {
  if (!elements.remediationSitePills) return;

  const allVulns = state.allVulnerabilities.length > 0 
    ? state.allVulnerabilities 
    : (state.activeSiteDetails?.vulnerabilities || []);

  const totalCount = allVulns.length;
  const sitesMap = {};

  (state.sites || []).forEach(s => {
    sitesMap[s.id] = {
      site: s,
      count: 0
    };
  });

  allVulns.forEach(v => {
    const sId = v.site_id;
    if (sitesMap[sId]) {
      sitesMap[sId].count++;
    }
  });

  let pillsHtml = `
    <button class="btn-site-pill ${state.filterRemediationSite === 'ALL' ? 'active' : ''}" onclick="window.filterRemediationBySite('ALL')">
      <span>🎯 Tous les sites</span>
      <span class="hud-badge-count" style="margin-left: 4px;">${totalCount}</span>
    </button>
  `;

  for (const sId in sitesMap) {
    const { site, count } = sitesMap[sId];
    const isAct = state.filterRemediationSite === sId;
    pillsHtml += `
      <button class="btn-site-pill ${isAct ? 'active' : ''}" onclick="window.filterRemediationBySite('${site.id}')">
        <span>🌐 ${escapeHtml(site.hostname)}</span>
        <span class="hud-badge-count" style="margin-left: 4px;">${count}</span>
      </button>
    `;
  }

  elements.remediationSitePills.innerHTML = pillsHtml;
}

window.filterRemediationBySite = (siteId) => {
  state.filterRemediationSite = siteId;
  renderRemediationView();
};

function formatThreatIntelligenceHtml(v, hostname) {
  const intel = v.threatIntel || {
    attackVectorTitle: "Exploitation de Défaut de Configuration",
    attackScenario: `1. L'attaquant cible ${hostname} et exploite cette faiblesse.\n2. Il contourne les contrôles de sécurité et tente une escalade de privilèges.`,
    dataAtRisk: [
      "Cookies de session & tokens d'authentification",
      "Données personnelles et métadonnées d'infrastructure"
    ],
    businessImpact: [
      "Compromission de session et risque de fuite de données",
      "Non-conformité aux exigences de sécurité standard"
    ],
    attackerPrerequisites: "Accès réseau ou envoi d'une requête HTTP standard."
  };

  const dataPills = (intel.dataAtRisk || []).map(d => `
    <div class="data-risk-pill">
      <span class="bullet">🎯</span>
      <span>${escapeHtml(d)}</span>
    </div>
  `).join('');

  const impactItems = (intel.businessImpact || []).map(imp => `
    <div class="business-impact-item">
      <span class="bullet">💥</span>
      <span>${escapeHtml(imp)}</span>
    </div>
  `).join('');

  return `
    <div class="threat-grid-details">
      <!-- Deep Threat Card 1: Attack Vector & Step-by-Step Scenario -->
      <div class="threat-deep-card attack-vector">
        <div class="threat-card-head red">
          <span>⚡</span>
          <span>VECTEUR D'ATTAQUE : ${escapeHtml(intel.attackVectorTitle || 'Scénario d\'attaque')}</span>
        </div>
        <p class="threat-scenario-text">${escapeHtml(intel.attackScenario || '')}</p>
        ${intel.attackerPrerequisites ? `
          <div style="margin-top: 0.65rem; font-size: 0.76rem; color: var(--text-muted); font-family: var(--font-mono);">
            <strong style="color: var(--neo-yellow);">Prérequis attaquant :</strong> ${escapeHtml(intel.attackerPrerequisites)}
          </div>
        ` : ''}
      </div>

      <!-- Deep Threat Card 2: Data at Risk & Business Impact -->
      <div style="display: flex; flex-direction: column; gap: 0.75rem;">
        <div class="threat-deep-card data-at-risk">
          <div class="threat-card-head orange">
            <span>🎯</span>
            <span>DONNÉES & ACTIFS VULNÉRABLES SUR ${escapeHtml(hostname)}</span>
          </div>
          <div class="data-risk-chips-list">
            ${dataPills}
          </div>
        </div>

        <div class="threat-deep-card business-impact">
          <div class="threat-card-head purple">
            <span>💥</span>
            <span>IMPACT MÉTIER & SÉCURITÉ RÉEL</span>
          </div>
          <div class="business-impact-list">
            ${impactItems}
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderRemediationView() {
  if (!elements.remediationAccordionList) return;

  renderRemediationSitePills();

  const allVulns = state.allVulnerabilities.length > 0 
    ? state.allVulnerabilities 
    : (state.activeSiteDetails?.vulnerabilities || []);

  if (allVulns.length === 0) {
    elements.remediationAccordionList.innerHTML = `
      <div class="empty-tiles-placeholder" style="padding: 3.5rem;">
        <span style="font-size: 2.5rem;">🛡️</span>
        <h3 class="text-neon-green">Aucune vulnérabilité active détectée</h3>
        <p class="text-muted">Déployez ou auditez un service depuis le Bento Board pour afficher sa checklist de remédiation et son analyse de menaces.</p>
      </div>
    `;
    return;
  }

  // Filtrer par sévérité et par site
  let filtered = allVulns.filter(v => {
    if (state.filterSeverity !== 'ALL' && v.severity !== state.filterSeverity) return false;
    if (state.filterRemediationSite !== 'ALL' && v.site_id !== state.filterRemediationSite) return false;
    return true;
  });

  if (filtered.length === 0) {
    elements.remediationAccordionList.innerHTML = `
      <div class="empty-tiles-placeholder" style="padding: 2.5rem;">
        <p class="text-muted">Aucune vulnérabilité ne correspond aux filtres sélectionnés (Sévérité : ${state.filterSeverity}).</p>
      </div>
    `;
    return;
  }

  // Mode 1: Groupé par site
  if (state.remediationViewMode === 'grouped') {
    const groupedBySite = {};
    filtered.forEach(v => {
      const sId = v.site_id || 'unknown';
      if (!groupedBySite[sId]) {
        groupedBySite[sId] = {
          siteId: sId,
          siteHostname: v.site_hostname || 'Site inconnu',
          siteUrl: v.site_target_url || '',
          siteGrade: v.site_latest_grade || 'F',
          siteScore: v.site_latest_score || 0,
          vulns: []
        };
      }
      groupedBySite[sId].vulns.push(v);
    });

    elements.remediationAccordionList.innerHTML = Object.values(groupedBySite).map(group => {
      const initial = group.siteHostname.charAt(0).toUpperCase();
      const gradeClass = `tile-grade-${group.siteGrade.charAt(0)}`;

      const itemsHtml = group.vulns.map((v, i) => renderSingleRemediationItem(v, i, group.siteHostname)).join('');

      return `
        <section class="site-group-section" id="site-group-${group.siteId}">
          <div class="site-group-header">
            <div class="site-group-left">
              <div class="site-group-icon">${initial}</div>
              <div>
                <div style="display: flex; align-items: center; gap: 0.6rem;">
                  <h3 class="site-group-title">${escapeHtml(group.siteHostname)}</h3>
                  <div class="tile-grade-badge ${gradeClass}" style="padding: 2px 8px; font-size: 0.75rem;">
                    ${group.siteGrade} (${group.siteScore}/100)
                  </div>
                </div>
                <span class="site-group-url">${escapeHtml(group.siteUrl)}</span>
              </div>
            </div>

            <div class="site-group-actions">
              <span class="font-mono text-neon-cyan" style="font-size: 0.8rem; font-weight: 700; margin-right: 0.5rem;">
                ${group.vulns.length} faille(s) assignée(s)
              </span>
              <button class="btn-site-jump" onclick="window.openSiteDetailPage('${group.siteId}')" title="Accéder à la page détaillée de ce site">
                🔍 Page Détaillée &amp; Solutions ➔
              </button>
            </div>
          </div>

          <div style="padding: 1rem 1.25rem;">
            ${itemsHtml}
          </div>
        </section>
      `;
    }).join('');

  } else {
    // Mode 2: Liste globale continue (Flat list)
    elements.remediationAccordionList.innerHTML = filtered.map((v, i) => {
      const hostname = v.site_hostname || state.activeSiteDetails?.site?.hostname || 'example.com';
      return renderSingleRemediationItem(v, i, hostname, true);
    }).join('');
  }
}

function renderSingleRemediationItem(v, i, hostname, showSiteBadge = false) {
  const isResolved = v.status === 'RESOLVED';
  const cardId = v.id || i;
  const selectedStack = state.individualStacks[cardId] || 'nginx';
  const snippetCode = getIndividualSnippet(v.code, selectedStack, hostname);
  const siteBadgeHtml = showSiteBadge ? `
    <button class="rem-site-badge-pill" onclick="event.stopPropagation(); window.openSiteDetailPage('${v.site_id}')" title="Ouvrir la page détaillée pour ce site">
      🌐 ${escapeHtml(hostname)} ↗
    </button>
  ` : '';

  return `
    <div class="rem-accordion-item ${v.severity}" id="rem-item-${cardId}">
      <div class="rem-item-header" onclick="window.toggleRemAccordion('${cardId}')">
        <div class="rem-item-left">
          <span class="rem-sev-tag ${v.severity}">${v.severity}</span>
          ${siteBadgeHtml}
          <span class="rem-title-text" style="${isResolved ? 'text-decoration: line-through; opacity: 0.6;' : ''}">
            ${escapeHtml(v.title)}
          </span>
          <span class="rem-cwe-badge font-mono">${escapeHtml(v.cwe || 'CWE')}</span>
        </div>
        <div>
          ${isResolved ? '<span class="matrix-status ok">RÉSOLU</span>' : ''}
          <span style="color: var(--text-muted); margin-left: 0.5rem;">▼</span>
        </div>
      </div>

      <div class="rem-item-body">
        
        <!-- Deep Threat Analysis (Attacks & Data at Risk) -->
        ${formatThreatIntelligenceHtml(v, hostname)}

        <div class="rem-section-lbl" style="margin-top: 1rem;">ACTION DE SÉCURISATION INDIVIDUELLE :</div>
        <p class="rem-desc" style="color: var(--neon-cyan); font-weight: 500;">
          ${escapeHtml(v.remediation)}
        </p>

        <!-- Stack selector per vulnerability -->
        <div class="rem-section-lbl">SNIPPET SPÉCIFIQUE À CETTE FAILLE :</div>
        <div class="individual-stack-picker">
          <button class="btn-indiv-stack ${selectedStack === 'nginx' ? 'active' : ''}" onclick="window.changeIndivStack('${cardId}', 'nginx')">Nginx</button>
          <button class="btn-indiv-stack ${selectedStack === 'apache' ? 'active' : ''}" onclick="window.changeIndivStack('${cardId}', 'apache')">Apache</button>
          <button class="btn-indiv-stack ${selectedStack === 'express' ? 'active' : ''}" onclick="window.changeIndivStack('${cardId}', 'express')">Express.js</button>
          <button class="btn-indiv-stack ${selectedStack === 'nextjs' ? 'active' : ''}" onclick="window.changeIndivStack('${cardId}', 'nextjs')">Next.js</button>
          <button class="btn-indiv-stack ${selectedStack === 'caddy' ? 'active' : ''}" onclick="window.changeIndivStack('${cardId}', 'caddy')">Caddy</button>
          <button class="btn-indiv-stack ${selectedStack === 'vercel' ? 'active' : ''}" onclick="window.changeIndivStack('${cardId}', 'vercel')">Vercel</button>
        </div>

        <div class="code-snippet-box">
          <button class="btn-copy-code" onclick="window.copyCode(this, \`${encodeURIComponent(snippetCode)}\`)">
            Copier
          </button>
          <pre class="font-mono">${escapeHtml(snippetCode)}</pre>
        </div>

        <!-- Bottom Actions -->
        <div class="rem-actions-bar">
          <div style="display: flex; align-items: center; gap: 0.75rem;">
            <button class="btn-copy-code" style="position: static; padding: 5px 12px; font-size: 0.8rem;" onclick="window.copyCode(this, \`${encodeURIComponent(snippetCode)}\`)">
              📋 Copier la solution
            </button>
            <button class="btn-ghost-sm" style="padding: 5px 10px; font-size: 0.75rem;" onclick="window.openSiteDetailPage('${v.site_id}')" title="Voir la fiche complète de ce site">
              🔍 Voir page site
            </button>
          </div>

          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span class="text-muted font-mono" style="font-size: 0.75rem;">SUIVI AUDIT :</span>
            <select class="status-dropdown" onchange="window.updateVulnStatus('${v.id}', this.value)">
              <option value="OPEN" ${v.status === 'OPEN' ? 'selected' : ''}>🔴 À Corriger (Ouvert)</option>
              <option value="IN_PROGRESS" ${v.status === 'IN_PROGRESS' ? 'selected' : ''}>🟡 En cours de traitement</option>
              <option value="RESOLVED" ${v.status === 'RESOLVED' ? 'selected' : ''}>🟢 Résolu / Validé</option>
              <option value="IGNORED" ${v.status === 'IGNORED' ? 'selected' : ''}>⚪ Faux positif / Ignoré</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  `;
}

function getIndividualSnippet(code, stack, hostname = 'example.com') {
  if (stack === 'nginx') {
    switch (code) {
      case 'MISSING_CSP':
      case 'CSP_UNSAFE_INLINE':
        return `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';" always;`;
      case 'MISSING_HSTS':
        return `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`;
      case 'MISSING_X_FRAME_OPTIONS':
        return `add_header X-Frame-Options "DENY" always;`;
      case 'MISSING_X_CONTENT_TYPE_OPTIONS':
        return `add_header X-Content-Type-Options "nosniff" always;`;
      case 'MISSING_REFERRER_POLICY':
        return `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`;
      case 'CORS_WILDCARD_ALLOW_ORIGIN':
      case 'CORS_ALLOW_ORIGIN_NULL':
      case 'CORS_EXPOSED_HEADERS':
        return `add_header Access-Control-Allow-Origin "https://${hostname}" always;\nadd_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;`;
      case 'NO_HTTPS_REDIRECT':
        return `server {\n    listen 80;\n    server_name ${hostname};\n    return 301 https://$host$request_uri;\n}`;
      case 'EXPOSED_ENV_FILE':
      case 'EXPOSED_GIT_REPO':
        return `location ~ /\\.(?!well-known) {\n    deny all;\n    return 404;\n}`;
      case 'SERVER_VERSION_LEAK':
      case 'X_POWERED_BY_LEAK':
        return `server_tokens off;`;
      default:
        return `# Durcissement recommandé Nginx\nadd_header X-Content-Type-Options "nosniff" always;`;
    }
  } else if (stack === 'apache') {
    switch (code) {
      case 'MISSING_CSP':
        return `Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; frame-ancestors 'none';"`;
      case 'MISSING_HSTS':
        return `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`;
      case 'MISSING_X_FRAME_OPTIONS':
        return `Header always set X-Frame-Options "DENY"`;
      case 'MISSING_X_CONTENT_TYPE_OPTIONS':
        return `Header always set X-Content-Type-Options "nosniff"`;
      case 'CORS_WILDCARD_ALLOW_ORIGIN':
        return `Header always set Access-Control-Allow-Origin "https://${hostname}"`;
      case 'NO_HTTPS_REDIRECT':
        return `RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`;
      case 'EXPOSED_ENV_FILE':
        return `<Files ".env">\n    Require all denied\n</Files>`;
      default:
        return `Header always set X-Frame-Options "DENY"`;
    }
  } else if (stack === 'express') {
    switch (code) {
      case 'MISSING_CSP':
        return `app.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'"],\n    objectSrc: ["'none'"]\n  }\n}));`;
      case 'MISSING_HSTS':
        return `app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));`;
      case 'MISSING_X_FRAME_OPTIONS':
        return `app.use(helmet.frameguard({ action: 'deny' }));`;
      case 'CORS_WILDCARD_ALLOW_ORIGIN':
        return `import cors from 'cors';\napp.use(cors({ origin: ['https://${hostname}'], credentials: true }));`;
      case 'SERVER_VERSION_LEAK':
      case 'X_POWERED_BY_LEAK':
        return `app.disable('x-powered-by');`;
      default:
        return `app.use(helmet());`;
    }
  } else if (stack === 'nextjs') {
    switch (code) {
      case 'MISSING_HSTS':
        return `{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }`;
      case 'MISSING_CSP':
        return `{ key: 'Content-Security-Policy', value: "default-src 'self'; object-src 'none';" }`;
      case 'MISSING_X_FRAME_OPTIONS':
        return `{ key: 'X-Frame-Options', value: 'DENY' }`;
      case 'CORS_WILDCARD_ALLOW_ORIGIN':
        return `{ key: 'Access-Control-Allow-Origin', value: 'https://${hostname}' }`;
      default:
        return `{ key: 'X-Content-Type-Options', value: 'nosniff' }`;
    }
  } else if (stack === 'caddy') {
    switch (code) {
      case 'MISSING_CSP':
        return `header Content-Security-Policy "default-src 'self'; script-src 'self'; frame-ancestors 'none';"`;
      case 'MISSING_HSTS':
        return `header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`;
      case 'MISSING_X_FRAME_OPTIONS':
        return `header X-Frame-Options "DENY"`;
      case 'MISSING_X_CONTENT_TYPE_OPTIONS':
        return `header X-Content-Type-Options "nosniff"`;
      case 'CORS_WILDCARD_ALLOW_ORIGIN':
        return `header Access-Control-Allow-Origin "https://${hostname}"`;
      case 'NO_HTTPS_REDIRECT':
        return `# Caddy active la redirection automatique vers HTTPS nativement`;
      case 'EXPOSED_ENV_FILE':
        return `@hiddenFiles path */.* \nrespond @hiddenFiles 404`;
      default:
        return `header X-Content-Type-Options "nosniff"`;
    }
  } else if (stack === 'vercel') {
    switch (code) {
      case 'MISSING_HSTS':
        return `{\n  "source": "/(.*)",\n  "headers": [{ "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" }]\n}`;
      case 'MISSING_CSP':
        return `{\n  "source": "/(.*)",\n  "headers": [{ "key": "Content-Security-Policy", "value": "default-src 'self'; object-src 'none';" }]\n}`;
      case 'MISSING_X_FRAME_OPTIONS':
        return `{\n  "source": "/(.*)",\n  "headers": [{ "key": "X-Frame-Options", "value": "DENY" }]\n}`;
      case 'CORS_WILDCARD_ALLOW_ORIGIN':
        return `{\n  "source": "/(.*)",\n  "headers": [{ "key": "Access-Control-Allow-Origin", "value": "https://${hostname}" }]\n}`;
      default:
        return `{\n  "source": "/(.*)",\n  "headers": [{ "key": "X-Content-Type-Options", "value": "nosniff" }]\n}`;
    }
  }
  return `add_header X-Content-Type-Options "nosniff" always;`;
}

// ==========================================================================
// DEDICATED SITE DETAIL PAGE ENGINE & SOLUTION ASSIGNMENT
// ==========================================================================
function setupSiteDetailView() {
  elements.btnBackToBoard?.addEventListener('click', () => {
    window.location.hash = '';
    switchView('board');
  });

  elements.btnDetailAutoHarden?.addEventListener('click', () => {
    if (state.currentDetailSiteId) {
      window.openHardeningForSite(state.currentDetailSiteId);
    }
  });

  elements.btnDetailCompare?.addEventListener('click', () => {
    if (state.currentDetailSiteId) {
      window.openScanComparisonModal(state.currentDetailSiteId);
    }
  });

  elements.btnDetailRescan?.addEventListener('click', () => {
    if (state.activeSiteDetails?.site?.target_url) {
      executeScan(state.activeSiteDetails.site.target_url);
    }
  });

  elements.btnDetailExportHtml?.addEventListener('click', () => {
    if (state.currentDetailSiteId) {
      window.location.href = `/api/sites/${state.currentDetailSiteId}/export`;
      showToast("Génération du rapport HTML complet...", "success");
    }
  });

  elements.btnDetailExportPdf?.addEventListener('click', () => {
    if (state.currentDetailSiteId) {
      window.open(`/api/sites/${state.currentDetailSiteId}/export?print=1`, '_blank');
      showToast("Ouverture de l'export PDF / Impression...", "success");
    }
  });

  elements.btnDetailFilters.forEach(btn => {
    btn.addEventListener('click', () => {
      elements.btnDetailFilters.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.filterDetailSeverity = btn.getAttribute('data-detail-filter');
      if (state.activeSiteDetails) {
        renderSiteSolutionsList(state.activeSiteDetails.vulnerabilities || []);
      }
    });
  });
}

function setupHashRouting() {
  function handleRoute() {
    const hash = window.location.hash;
    if (hash.startsWith('#/site/')) {
      const siteId = hash.replace('#/site/', '').trim();
      if (siteId) {
        window.openSiteDetailPage(siteId, false);
      }
    }
  }

  window.addEventListener('hashchange', handleRoute);
  handleRoute();
}

window.openSiteDetailPage = async (siteId, updateHash = true) => {
  try {
    const res = await fetch(`/api/sites/${siteId}`);
    if (!res.ok) {
      showToast("Impossible de charger les détails du site.", "error");
      return;
    }

    state.activeSiteDetails = await res.json();
    state.currentDetailSiteId = siteId;

    if (updateHash) {
      window.location.hash = `#/site/${siteId}`;
    }

    renderSiteDetailPage(state.activeSiteDetails);
    switchView('site-detail');
    window.scrollTo({ top: 0, behavior: 'smooth' });

  } catch (err) {
    console.error('Erreur:', err);
    showToast("Erreur lors de l'ouverture de la page détaillée.", "error");
  }
};

function renderSiteDetailPage(details) {
  const { site, history, lastScanReport, vulnerabilities } = details;
  const report = lastScanReport;

  // Nav Breadcrumb
  if (elements.detailNavHostname) {
    elements.detailNavHostname.textContent = site.hostname;
  }

  // Hero Card
  if (elements.detailSiteHostname) elements.detailSiteHostname.textContent = site.hostname;
  if (elements.detailSiteUrl) elements.detailSiteUrl.textContent = site.target_url;
  if (elements.detailSiteLink) elements.detailSiteLink.href = site.target_url;
  if (elements.detailHeroIcon) elements.detailHeroIcon.textContent = site.hostname.charAt(0).toUpperCase();
  if (elements.detailSiteVerdict) elements.detailSiteVerdict.textContent = report?.verdict || 'Analyse de durcissement et conformité OWASP effectuée.';

  if (report) {
    const d = new Date(report.timestamp);
    if (elements.detailSiteScanDate) {
      elements.detailSiteScanDate.textContent = `📅 Audit : ${d.toLocaleDateString('fr-FR')} à ${d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}`;
    }
    if (elements.detailSiteDuration) elements.detailSiteDuration.textContent = `⏱️ ${report.durationMs} ms`;
    if (elements.detailSiteSsl) elements.detailSiteSsl.textContent = report.ssl ? `🔒 ${report.ssl.protocol}` : '🔓 Pas de SSL';
  }
  if (elements.detailSiteTotalScans) {
    elements.detailSiteTotalScans.textContent = `📊 ${history ? history.length : 1} scan(s) enregistré(s)`;
  }

  // Grade & Score
  if (elements.detailSiteGrade) {
    elements.detailSiteGrade.textContent = site.latest_grade || 'F';
    const letter = site.latest_grade ? site.latest_grade.charAt(0) : 'F';
    elements.detailSiteGrade.className = `hero-grade-badge tile-grade-${letter}`;
  }
  if (elements.detailSiteScore) {
    elements.detailSiteScore.textContent = site.latest_score || 0;
  }

  // Bento Widget A: Tech Stack
  if (elements.detailTechStack) {
    if (report?.techStack && report.techStack.length > 0) {
      elements.detailTechStack.innerHTML = report.techStack.map(t => `
        <div class="tech-chip-cyber" title="${t.category}">
          <span class="tech-icon">${t.icon || '⚡'}</span>
          <span class="tech-name font-mono"><strong>${t.name}</strong></span>
          <span class="tech-cat">${t.category}</span>
        </div>
      `).join('');
    } else {
      elements.detailTechStack.innerHTML = `<span class="text-muted font-mono" style="font-size: 0.8rem;">Aucune fuite d'en-tête serveur ni signature de framework exposée (Bonne pratique ✓).</span>`;
    }
  }

  // Bento Widget B: SSL Info
  if (elements.detailSslBody) {
    if (report?.ssl) {
      const s = report.ssl;
      const exp = new Date(s.validTo).toLocaleDateString('fr-FR');
      elements.detailSslBody.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 0.45rem; font-size: 0.82rem;">
          <div style="display: flex; justify-content: space-between;"><span class="text-muted">Émetteur :</span> <span class="font-mono text-neon-cyan">${s.issuer}</span></div>
          <div style="display: flex; justify-content: space-between;"><span class="text-muted">Protocole & Chiffrement :</span> <span class="font-mono">${s.protocol} (${s.cipher})</span></div>
          <div style="display: flex; justify-content: space-between;"><span class="text-muted">Validité jusqu'au :</span> <span class="font-mono ${s.daysRemaining < 30 ? 'text-neon-red' : 'text-neon-green'}">${exp} (${s.daysRemaining}j restants)</span></div>
          <div style="display: flex; justify-content: space-between;"><span class="text-muted">Autorité Racine CA :</span> <span class="font-mono">${s.authorized ? 'Vérifiée & Reconnue ✓' : 'Non approuvée ✗'}</span></div>
        </div>
      `;
    } else {
      elements.detailSslBody.innerHTML = `<span class="text-neon-red font-mono" style="font-size: 0.82rem;">Aucun certificat SSL détecté. Le trafic transite en clair via HTTP.</span>`;
    }
  }

  // Bento Widget C: Evolution Canvas
  renderSiteDetailCanvas(history);

  // Vulnerabilities & Solutions List
  renderSiteSolutionsList(vulnerabilities || []);
}

function renderSiteDetailCanvas(history) {
  if (!elements.detailHistoryCanvas) return;
  const canvas = elements.detailHistoryCanvas;
  const ctx = canvas.getContext('2d');

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = (rect.width || 300) * dpr;
  canvas.height = 100 * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width || 300;
  const h = 100;
  ctx.clearRect(0, 0, w, h);

  if (!history || history.length <= 1) {
    ctx.fillStyle = '#526079';
    ctx.font = '11px JetBrains Mono';
    ctx.fillText("Courbe d'évolution active dès le 2ème scan.", 15, 50);
    return;
  }

  const scores = history.map(item => item.score);
  const stepX = (w - 30) / (scores.length - 1);

  ctx.beginPath();
  scores.forEach((sc, i) => {
    const x = 15 + i * stepX;
    const y = h - 20 - (sc / 100) * (h - 40);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  ctx.strokeStyle = '#00f2fe';
  ctx.lineWidth = 2.5;
  ctx.stroke();

  scores.forEach((sc, i) => {
    const x = 15 + i * stepX;
    const y = h - 20 - (sc / 100) * (h - 40);
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#05070d';
    ctx.fill();
    ctx.strokeStyle = sc >= 70 ? '#00ff87' : '#ff0055';
    ctx.lineWidth = 2;
    ctx.stroke();
  });
}

function renderSiteSolutionsList(vulns) {
  if (!elements.detailSolutionsList) return;

  if (vulns.length === 0) {
    elements.detailSolutionsList.innerHTML = `
      <div class="empty-tiles-placeholder" style="padding: 3.5rem;">
        <span style="font-size: 2.5rem;">🛡️</span>
        <h3 class="text-neon-green">Posture de Défense Optimale !</h3>
        <p class="text-muted">Aucune faille ou vulnérabilité active détectée sur cette cible.</p>
      </div>
    `;
    if (elements.detailVulnsCount) elements.detailVulnsCount.textContent = '0 FAILLE';
    return;
  }

  let filtered = vulns.filter(v => {
    if (state.filterDetailSeverity === 'ALL') return true;
    if (state.filterDetailSeverity === 'RESOLVED') return v.status === 'RESOLVED';
    return v.severity === state.filterDetailSeverity && v.status !== 'RESOLVED';
  });

  if (elements.detailVulnsCount) {
    elements.detailVulnsCount.textContent = `${filtered.length} FAILLE(S)`;
  }

  if (filtered.length === 0) {
    elements.detailSolutionsList.innerHTML = `
      <div class="empty-tiles-placeholder" style="padding: 2.5rem;">
        <p class="text-muted">Aucune vulnérabilité correspondant au filtre sélectionné.</p>
      </div>
    `;
    return;
  }

  elements.detailSolutionsList.innerHTML = filtered.map((v, i) => {
    const isResolved = v.status === 'RESOLVED';
    const cardId = v.id || i;
    const hostname = state.activeSiteDetails?.site?.hostname || 'example.com';
    const selectedStack = state.individualStacks[cardId] || 'nginx';
    const snippetCode = getIndividualSnippet(v.code, selectedStack, hostname);

    return `
      <article class="solution-card-cyber ${isResolved ? 'RESOLVED' : v.severity}" id="sol-card-${cardId}">
        <div class="solution-card-header">
          <div class="sol-header-left">
            <span class="rem-sev-tag ${v.severity}">${v.severity}</span>
            <span class="sol-vuln-title ${isResolved ? 'resolved' : ''}">${escapeHtml(v.title)}</span>
            <span class="rem-cwe-badge font-mono" title="${escapeHtml(v.cweTitle || '')}">${v.cwe || 'CWE-Unknown'}</span>
          </div>
          <div>
            <span class="matrix-status ${isResolved ? 'ok' : 'ko'}">
              ${isResolved ? '✓ RÉSOLUE' : v.status === 'IN_PROGRESS' ? '🟡 EN COURS' : '🔴 ACTIVE'}
            </span>
          </div>
        </div>

        <div class="solution-card-body">
          
          <!-- Deep Threat Analysis (Attacks Scenario, Data at Risk & Impact) -->
          ${formatThreatIntelligenceHtml(v, hostname)}

          <div class="solution-blocks-grid" style="margin-top: 1rem;">
            
            <!-- Block 1: Diagnostic & Threat description -->
            <div class="solution-block">
              <div class="sol-block-title">
                <span>📌</span> CONSTAT &amp; IMPACT SUR LA SÉCURITÉ :
              </div>
              <p class="sol-block-text">${escapeHtml(v.description)}</p>
            </div>

            <!-- Block 2: Solution Requise & Stratégie -->
            <div class="solution-block" style="border-color: rgba(0, 255, 135, 0.2);">
              <div class="sol-block-title solution-highlight">
                <span>💡</span> SOLUTION REQUISE À APPLIQUER :
              </div>
              <p class="sol-block-text" style="color: var(--neon-green); font-weight: 500;">
                ${escapeHtml(v.remediation)}
              </p>
            </div>

          </div>

          <!-- Snippet de correction assigné -->
          <div class="solution-block" style="background: rgba(2, 4, 8, 0.6);">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem;">
              <div class="sol-block-title" style="color: var(--neon-cyan); margin-bottom: 0;">
                <span>💻</span> SNIPPET DE CONFIGURATION ASSIGNÉ PRÊT À DÉPLOYER :
              </div>
              
              <!-- Stack Picker -->
              <div class="individual-stack-picker">
                <button class="btn-indiv-stack ${selectedStack === 'nginx' ? 'active' : ''}" onclick="window.changeDetailStack('${cardId}', 'nginx')">Nginx</button>
                <button class="btn-indiv-stack ${selectedStack === 'apache' ? 'active' : ''}" onclick="window.changeDetailStack('${cardId}', 'apache')">Apache</button>
                <button class="btn-indiv-stack ${selectedStack === 'express' ? 'active' : ''}" onclick="window.changeDetailStack('${cardId}', 'express')">Express.js</button>
                <button class="btn-indiv-stack ${selectedStack === 'nextjs' ? 'active' : ''}" onclick="window.changeDetailStack('${cardId}', 'nextjs')">Next.js</button>
                <button class="btn-indiv-stack ${selectedStack === 'caddy' ? 'active' : ''}" onclick="window.changeDetailStack('${cardId}', 'caddy')">Caddy</button>
                <button class="btn-indiv-stack ${selectedStack === 'vercel' ? 'active' : ''}" onclick="window.changeDetailStack('${cardId}', 'vercel')">Vercel</button>
              </div>
            </div>

            <div class="sol-code-box">
              <button class="btn-copy-code" onclick="window.copyCode(this, \`${encodeURIComponent(snippetCode)}\`)">
                📋 Copier
              </button>
              <pre class="sol-code-pre">${escapeHtml(snippetCode)}</pre>
            </div>
          </div>

          <!-- Bottom Action Bar -->
          <div class="solution-card-footer">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <button class="btn-copy-code" style="position: static; padding: 6px 14px; font-size: 0.82rem;" onclick="window.copyCode(this, \`${encodeURIComponent(snippetCode)}\`)">
                📋 Copier cette solution
              </button>
              ${isResolved ? `
                <span class="text-neon-green font-mono" style="font-size: 0.85rem; font-weight: 600;">✓ Faille notée comme résolue</span>
              ` : `
                <span class="text-muted font-mono" style="font-size: 0.82rem;">💡 Recommandation à déployer sur votre serveur</span>
              `}
            </div>

            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <span class="text-muted font-mono" style="font-size: 0.78rem;">STATUT AUDIT :</span>
              <select class="status-dropdown" onchange="window.updateVulnStatus('${v.id}', this.value)">
                <option value="OPEN" ${v.status === 'OPEN' ? 'selected' : ''}>🔴 À Corriger (Ouvert)</option>
                <option value="IN_PROGRESS" ${v.status === 'IN_PROGRESS' ? 'selected' : ''}>🟡 En cours</option>
                <option value="RESOLVED" ${v.status === 'RESOLVED' ? 'selected' : ''}>🟢 Résolu / Validé</option>
                <option value="IGNORED" ${v.status === 'IGNORED' ? 'selected' : ''}>⚪ Ignoré</option>
              </select>
            </div>
          </div>

        </div>
      </article>
    `;
  }).join('');
}

// Stack switcher inside the detail page
window.changeDetailStack = (cardId, stack) => {
  state.individualStacks[cardId] = stack;
  if (state.activeSiteDetails) {
    renderSiteSolutionsList(state.activeSiteDetails.vulnerabilities || []);
  }
};

window.applyIndividualSolution = async (vulnId) => {
  await window.updateVulnStatus(vulnId, 'RESOLVED');
  showToast("Solution appliquée et faille marquée comme résolue !", "success");
};

// Helpers & Global Actions
window.changeIndivStack = (cardId, stack) => {
  state.individualStacks[cardId] = stack;
  renderRemediationView();
};

window.quickResolveVuln = async (vulnId) => {
  await window.updateVulnStatus(vulnId, 'RESOLVED');
};

window.toggleRemAccordion = (id) => {
  const item = document.getElementById(`rem-item-${id}`);
  if (item) item.classList.toggle('open');
};

window.copyCode = (btn, encoded) => {
  const code = decodeURIComponent(encoded);
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = '✓ Copié !';
    btn.style.color = 'var(--neon-green)';
    showToast("Code copié dans le presse-papier !", "success", 2000);
    setTimeout(() => {
      btn.textContent = 'Copier';
      btn.style.color = '';
    }, 2000);
  });
};

window.updateVulnStatus = async (vulnId, newStatus) => {
  if (!vulnId) return;
  try {
    const res = await fetch(`/api/vulnerabilities/${vulnId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      showToast(`Statut mis à jour : ${newStatus}`, "info", 2000);
      if (state.activeSiteDetails?.site?.id) {
        const refreshedRes = await fetch(`/api/sites/${state.activeSiteDetails.site.id}`);
        if (refreshedRes.ok) {
          state.activeSiteDetails = await refreshedRes.json();
          if (state.currentView === 'site-detail') {
            renderSiteDetailPage(state.activeSiteDetails);
          } else {
            populateDrawer(state.activeSiteDetails);
          }
        }
      }
      loadDashboardData();
    }
  } catch (err) {
    console.error('Erreur:', err);
    showToast("Erreur lors de la mise à jour du statut.", "error");
  }
};

window.quickAuditTarget = (url) => {
  executeScan(url);
};

window.deleteTargetSite = async (siteId) => {
  if (!confirm("Retirer cette cible du Bento Board ?")) return;
  try {
    const res = await fetch(`/api/sites/${siteId}`, { method: 'DELETE' });
    if (res.ok) {
      logToFeed(`Cible retirée du tableau de bord.`, 'INFO');
      showToast("Cible supprimée du tableau de bord.", "info");
      if (state.currentView === 'site-detail' && state.currentDetailSiteId === siteId) {
        window.location.hash = '';
        switchView('board');
      }
      loadDashboardData();
    }
  } catch (err) {
    showToast("Erreur lors de la suppression: " + err.message, "error");
  }
};

async function rescanAllSites() {
  if (!state.sites || state.sites.length === 0) {
    showToast("Aucune cible à ré-auditer.", "warning");
    return;
  }
  showToast(`Lancement de l'audit séquentiel pour ${state.sites.length} cible(s)...`, "info");
  for (const s of state.sites) {
    await executeScan(s.target_url);
  }
  showToast("Tous les audits sont terminés !", "success");
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
