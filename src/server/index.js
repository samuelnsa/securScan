/**
 * Serveur API REST SecurScan & Service de monitoring
 */
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanTarget } from '../scanner/index.js';
import { analyzeRegression } from './regression.js';
import { generateHardeningPatch } from './patchGenerator.js';
import {
  getOrCreateSite,
  getLastScanForSite,
  saveScan,
  getAllSites,
  getSiteDetails,
  getScanById,
  updateVulnerabilityStatus,
  resolveAllSiteVulnerabilities,
  deleteSite,
  getGlobalSummary,
  getAllVulnerabilities
} from './storage.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Servir les fichiers statiques du dashboard (Étape 3)
const clientDir = path.resolve(__dirname, '../client');
app.use(express.static(clientDir));

// ==========================================
// ROUTES API REST
// ==========================================

// 1. Déclencher un scan
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: "L'URL de la cible est obligatoire." });
  }

  try {
    // Obtenir ou créer l'entrée de site
    const site = getOrCreateSite(url);

    // Récupérer le scan précédent pour l'analyse de régression
    const previousScan = getLastScanForSite(site.id);

    // Exécuter le scan de sécurité
    const report = await scanTarget(url);

    // Analyser les régressions par rapport au scan antérieur
    const regression = analyzeRegression(previousScan, report);

    // Enregistrer le nouveau scan et synchroniser les vulnérabilités
    const { scanId } = saveScan(site.id, report, regression);

    return res.json({
      success: true,
      siteId: site.id,
      scanId,
      report,
      regression
    });
  } catch (err) {
    console.error('Erreur lors du scan :', err);
    return res.status(500).json({ error: err.message || "Erreur interne pendant l'audit." });
  }
});

// 2. Récupérer le résumé global
app.get('/api/summary', (req, res) => {
  try {
    const summary = getGlobalSummary();
    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Liste de tous les sites enregistrés
app.get('/api/sites', (req, res) => {
  try {
    const sites = getAllSites();
    res.json(sites);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Détails d'un site (historique, failles, rapport)
app.get('/api/sites/:id', (req, res) => {
  try {
    const details = getSiteDetails(req.params.id);
    if (!details) {
      return res.status(404).json({ error: 'Site non trouvé.' });
    }
    res.json(details);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Supprimer un site (cascade: supprime scans et vulnérabilités associés)
app.delete('/api/sites/:id', (req, res) => {
  try {
    deleteSite(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5b. Comparaison entre deux scans
app.get('/api/scans/:id1/compare/:id2', (req, res) => {
  try {
    const scan1 = getScanById(req.params.id1);
    const scan2 = getScanById(req.params.id2);

    if (!scan1 || !scan2) {
      return res.status(404).json({ error: 'Un ou plusieurs scans introuvables.' });
    }

    let report1, report2;
    try { report1 = JSON.parse(scan1.raw_json); } catch { report1 = {}; }
    try { report2 = JSON.parse(scan2.raw_json); } catch { report2 = {}; }

    const vulns1 = new Set((report1.vulnerabilities || []).map(v => v.code));
    const vulns2 = new Set((report2.vulnerabilities || []).map(v => v.code));

    const newIssues = [...vulns2].filter(c => !vulns1.has(c));
    const resolvedIssues = [...vulns1].filter(c => !vulns2.has(c));
    const persistentIssues = [...vulns1].filter(c => vulns2.has(c));

    res.json({
      scan1: { id: scan1.id, score: scan1.score, grade: scan1.grade, timestamp: scan1.timestamp },
      scan2: { id: scan2.id, score: scan2.score, grade: scan2.grade, timestamp: scan2.timestamp },
      scoreDiff: (scan2.score || 0) - (scan1.score || 0),
      newIssues: newIssues.map(code => (report2.vulnerabilities || []).find(v => v.code === code)),
      resolvedIssues: resolvedIssues.map(code => (report1.vulnerabilities || []).find(v => v.code === code)),
      persistentIssues: persistentIssues.length,
      totalVulns1: vulns1.size,
      totalVulns2: vulns2.size
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5c. Export HTML / PDF d'un rapport de scan
app.get('/api/sites/:id/export', (req, res) => {
  try {
    const details = getSiteDetails(req.params.id);
    if (!details) return res.status(404).json({ error: 'Site introuvable.' });

    const report = details.lastScanReport;
    const site = details.site;
    const vulns = details.vulnerabilities || [];
    const isPrint = req.query.print === '1' || req.query.format === 'pdf';

    const html = generateExportHTML(site, report, vulns, details.history, { isPrint });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (!isPrint && req.query.download !== '0') {
      res.setHeader('Content-Disposition', `attachment; filename="securscan-report-${site.hostname}.html"`);
    }
    res.send(html);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5d. Liste globale de toutes les vulnérabilités (avec filtres site et sévérité)
app.get('/api/vulnerabilities', (req, res) => {
  try {
    const { severity, siteId, status } = req.query;
    const vulns = getAllVulnerabilities({ severity, siteId, status });
    res.json(vulns);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. Mettre à jour le statut d'une vulnérabilité (Remédiation individuelle)
app.patch('/api/vulnerabilities/:id', (req, res) => {
  const { status } = req.body;
  if (!status) {
    return res.status(400).json({ error: 'Le champ status est requis.' });
  }

  try {
    const updated = updateVulnerabilityStatus(req.params.id, status);
    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 7. Génération d'un patch complet de durcissement (Full Auto-Hardening Kit)
app.post('/api/patch/generate', (req, res) => {
  const { vulnerabilities, stack, hostname } = req.body;
  if (!vulnerabilities || !Array.isArray(vulnerabilities)) {
    return res.status(400).json({ error: 'Liste de vulnérabilités requise.' });
  }

  try {
    const patch = generateHardeningPatch(vulnerabilities, stack || 'nginx', hostname || 'example.com');
    res.json(patch);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 8. Patch de durcissement spécifique pour un site enregistré
app.get('/api/sites/:id/patch', (req, res) => {
  const stack = req.query.stack || 'nginx';
  try {
    const details = getSiteDetails(req.params.id);
    if (!details) {
      return res.status(404).json({ error: 'Site introuvable.' });
    }

    const openVulns = (details.vulnerabilities || []).filter(v => v.status !== 'RESOLVED');
    const patch = generateHardeningPatch(openVulns, stack, details.site.hostname);
    res.json({
      ...patch,
      totalIssuesAddressed: openVulns.length,
      siteId: details.site.id,
      hostname: details.site.hostname
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 9. Sécurisation globale : marquer toutes les failles comme résolues
app.post('/api/sites/:id/resolve-all', (req, res) => {
  try {
    const result = resolveAllSiteVulnerabilities(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================================================
// HTML EXPORT GENERATOR
// ==========================================================================
function generateExportHTML(site, report, vulns, history, options = {}) {
  const isPrint = !!options.isPrint;
  const sevColors = { CRITICAL: '#ff0055', HIGH: '#f97316', MEDIUM: '#ffb703', LOW: '#4facfe', INFO: '#94a3b8' };

  const vulnRows = vulns.map(v => `
    <tr>
      <td><span style="color: ${sevColors[v.severity] || '#fff'}; font-weight: 700; font-family: monospace;">${v.severity}</span></td>
      <td><strong>${v.title}</strong></td>
      <td style="font-family: monospace; font-size: 0.85rem;">${v.cwe || '-'}</td>
      <td><span style="padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; background: ${v.status === 'RESOLVED' ? 'rgba(0,255,135,0.15)' : v.status === 'OPEN' ? 'rgba(255,0,85,0.15)' : 'rgba(255,183,3,0.15)'}; color: ${v.status === 'RESOLVED' ? '#00ff87' : v.status === 'OPEN' ? '#ff0055' : '#ffb703'};">${v.status}</span></td>
      <td style="font-size: 0.85rem; line-height: 1.4;">${v.remediation || '-'}</td>
    </tr>
  `).join('');

  const historyRows = (history || []).map(h => `
    <tr>
      <td>${new Date(h.timestamp).toLocaleDateString('fr-FR')} ${new Date(h.timestamp).toLocaleTimeString('fr-FR')}</td>
      <td><strong style="font-size: 1.1rem; color: #00f2fe;">${h.grade}</strong></td>
      <td style="font-family: monospace;">${h.score}/100</td>
      <td>${h.passed_count || 0} ✓ / ${h.failed_count || 0} ✗</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecurScan // Rapport d'Audit & Sécurité – ${site.hostname}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0a0e1a; color: #f1f5f9; font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; padding: 2rem; line-height: 1.6; }
    .container { max-width: 980px; margin: 0 auto; position: relative; }
    .print-bar { display: flex; justify-content: space-between; align-items: center; background: #0f172a; border: 2px solid #00f2fe; border-radius: 8px; padding: 0.75rem 1.25rem; margin-bottom: 2rem; box-shadow: 0 4px 20px rgba(0,242,254,0.15); }
    .print-btn { background: #00f2fe; color: #000; border: none; font-weight: 700; padding: 8px 18px; border-radius: 6px; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; font-size: 0.95rem; }
    .print-btn:hover { background: #38bdf8; }
    .back-btn { background: transparent; color: #94a3b8; border: 1px solid #334155; padding: 8px 14px; border-radius: 6px; text-decoration: none; font-size: 0.85rem; }
    .back-btn:hover { color: #fff; border-color: #64748b; }
    .report-header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid rgba(0,242,254,0.3); padding-bottom: 1.5rem; margin-bottom: 1.5rem; position: relative; }
    .brand-h { font-size: 1.8rem; font-weight: 800; color: #00f2fe; letter-spacing: -0.5px; }
    .brand-h span { color: #fff; }
    h2 { font-size: 1.25rem; color: #00f2fe; margin: 2rem 0 1rem; border-bottom: 1px solid rgba(0,242,254,0.2); padding-bottom: 0.4rem; display: flex; align-items: center; gap: 8px; }
    .meta { color: #94a3b8; font-size: 0.9rem; margin-top: 0.5rem; line-height: 1.6; }
    .score-box { display: flex; align-items: center; gap: 2.5rem; background: rgba(15,23,42,0.85); border: 2px solid rgba(0,242,254,0.3); border-radius: 12px; padding: 1.5rem 2rem; margin: 1.5rem 0; }
    .score-grade { font-size: 3.5rem; font-weight: 900; color: ${site.latest_score >= 80 ? '#00ff87' : site.latest_score >= 60 ? '#facc15' : '#ff0055'}; line-height: 1; }
    .score-number { font-size: 2.2rem; font-family: monospace; font-weight: 700; color: #fff; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0 2rem; background: rgba(15,23,42,0.5); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 0.9rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.07); font-size: 0.88rem; }
    th { color: #00f2fe; font-weight: 700; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.6px; background: rgba(0,242,254,0.06); }
    .footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid rgba(255,255,255,0.1); color: #64748b; font-size: 0.8rem; text-align: center; }
    .tech-chip { display: inline-block; padding: 4px 12px; background: rgba(0,242,254,0.12); border: 1px solid rgba(0,242,254,0.25); border-radius: 16px; font-size: 0.82rem; margin: 4px; color: #38bdf8; font-family: monospace; }
    .spiderweb-corner { position: absolute; top: -10px; right: -10px; width: 100px; height: 100px; opacity: 0.2; pointer-events: none; }
    
    @media print {
      body { background: #fff !important; color: #0f172a !important; padding: 0.5cm !important; }
      .no-print { display: none !important; }
      .score-box { background: #f8fafc !important; border: 2px solid #0284c7 !important; color: #0f172a !important; }
      .score-number { color: #0f172a !important; }
      table { background: #fff !important; border: 1px solid #cbd5e1 !important; page-break-inside: auto; }
      tr { page-break-inside: avoid; page-break-after: auto; }
      th { background: #f1f5f9 !important; color: #0369a1 !important; border-bottom: 2px solid #0369a1 !important; }
      td { border-bottom: 1px solid #e2e8f0 !important; color: #1e293b !important; }
      h1, h2, .brand-h { color: #0369a1 !important; }
      .meta { color: #475569 !important; }
      .tech-chip { background: #f1f5f9 !important; border-color: #cbd5e1 !important; color: #0369a1 !important; }
      .footer { color: #64748b !important; border-top-color: #cbd5e1 !important; }
    }
  </style>
</head>
<body>
  <div class="container">
    
    <div class="print-bar no-print">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 1.2rem;">📑</span>
        <strong>Rapport d'Audit Cyber SecurScan (Prêt pour Export PDF)</strong>
      </div>
      <div style="display: flex; gap: 10px;">
        <a href="javascript:history.back()" class="back-btn">⬅️ Revenir au Dashboard</a>
        <button class="print-btn" onclick="window.print()">
          🖨️ Enregistrer en PDF / Imprimer
        </button>
      </div>
    </div>

    <div class="report-header">
      <svg class="spiderweb-corner" viewBox="0 0 100 100" fill="none" stroke="#00f2fe" stroke-width="1.5">
        <path d="M100 0 L0 0 M100 0 L100 100 M100 0 L20 80 M100 0 L50 50 M100 0 L80 20" />
        <path d="M100 20 Q80 20 80 0" />
        <path d="M100 45 Q55 45 55 0" />
        <path d="M100 70 Q30 60 30 0" />
      </svg>
      <div>
        <div class="brand-h">SECUR<span>SCAN</span> <span style="font-size: 0.85rem; color: #38bdf8; font-family: monospace; border: 1px solid #38bdf8; padding: 2px 6px; border-radius: 4px; margin-left: 8px;">AUDIT DAST</span></div>
        <p class="meta">
          Cible analysée : <strong>${site.hostname}</strong> (${site.target_url})<br>
          Généré le : ${new Date().toLocaleDateString('fr-FR')} à ${new Date().toLocaleTimeString('fr-FR')}<br>
          Historique : ${history ? history.length : 0} cycle(s) d'audit passif enregistrés
        </p>
      </div>
      <div style="text-align: right;">
        <span style="font-size: 0.8rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px;">Classification</span><br>
        <strong style="color: #00f2fe; font-size: 1rem;">CONFIDENTIEL // AUDIT CYBER</strong>
      </div>
    </div>

    <div class="score-box">
      <div class="score-grade">${site.latest_grade}</div>
      <div>
        <div class="score-number">${site.latest_score}/100</div>
        <div style="color: #94a3b8; font-size: 1rem; margin-top: 4px;">${report?.verdict || 'Analyse de défense terminée'}</div>
      </div>
    </div>

    ${report?.techStack && report.techStack.length > 0 ? `
      <h2>🔍 Technologies Détectées (${report.techStack.length})</h2>
      <div style="margin-bottom: 1.5rem;">${report.techStack.map(t => `<span class="tech-chip">${t.icon || '⚡'} ${t.name} (${t.category})</span>`).join('')}</div>
    ` : ''}

    <h2>⚠️ Vulnérabilités & Recommandations de Remédiation (${vulns.length})</h2>
    ${vulns.length > 0 ? `
      <table>
        <thead><tr><th style="width: 110px;">Sévérité</th><th>Titre de la faille</th><th style="width: 90px;">CWE</th><th style="width: 100px;">Statut</th><th>Solution requise</th></tr></thead>
        <tbody>${vulnRows}</tbody>
      </table>
    ` : '<p style="color: #00ff87; padding: 1rem; background: rgba(0,255,135,0.08); border-radius: 6px;">✅ Aucune faille de sécurité détectée sur les en-têtes et le protocole HTTP. Excellent !</p>'}

    ${history && history.length > 0 ? `
      <h2>📊 Historique des Audits Antérieurs</h2>
      <table>
        <thead><tr><th>Date & Heure</th><th>Note</th><th>Score Global</th><th>Vérifications</th></tr></thead>
        <tbody>${historyRows}</tbody>
      </table>
    ` : ''}

    ${report?.ssl ? `
      <h2>🔒 Certificat & Chiffrement SSL/TLS</h2>
      <table>
        <tbody>
          <tr><td style="font-weight: 600; width: 220px;">Autorité de Certification</td><td>${report.ssl.issuer}</td></tr>
          <tr><td style="font-weight: 600;">Protocole & Chiffrement</td><td>${report.ssl.protocol} (${report.ssl.cipher})</td></tr>
          <tr><td style="font-weight: 600;">Expiration du Certificat</td><td>${new Date(report.ssl.validTo).toLocaleDateString('fr-FR')} (${report.ssl.daysRemaining} jours restants)</td></tr>
          <tr><td style="font-weight: 600;">Validation Chaîne CA</td><td>${report.ssl.authorized ? '<span style="color: #00ff87;">✓ Valide & Approuvée</span>' : '<span style="color: #ff0055;">✗ Non approuvée</span>'}</td></tr>
        </tbody>
      </table>
    ` : ''}

    <div class="footer">
      <p><strong>SecurScan Cyber Defense Suite</strong> // Audit passif automatisé conforme OWASP Top 10 &amp; CWE.</p>
      <p>Ce document est un rapport d'audit technique indépendant contenant des recommandations de durcissement.</p>
    </div>
  </div>

  ${isPrint ? `
  <script>
    window.addEventListener('load', function() {
      setTimeout(function() {
        window.print();
      }, 400);
    });
  </script>
  ` : ''}
</body>
</html>`;
}

// Fallback SPA pour toute route non gérée par l'API
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Route API introuvable.' });
  }
  res.sendFile(path.join(clientDir, 'index.html'));
});

// Export app pour Vercel / serverless
export { app };
export default app;

// Démarrage du serveur local avec gestion dynamique du port
function startServer(portToTry) {
  const server = app.listen(portToTry, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                  🛡️  SECURSCAN v2.0 LANCÉ                     ║
╠═══════════════════════════════════════════════════════════════╣
║  📡 Interface Web : http://localhost:${portToTry}                     ║
║  🔌 API REST      : http://localhost:${portToTry}/api/summary             ║
║  💾 Base SQLite   : ./data/securscan.db                       ║
╚═══════════════════════════════════════════════════════════════╝
    `);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`⚠️  Le port ${portToTry} est déjà utilisé, bascule sur le port ${portToTry + 1}...`);
      startServer(portToTry + 1);
    } else {
      console.error('Erreur serveur :', err);
    }
  });
}

// Ne pas écouter si exécuté comme fonction serverless Vercel
if (!process.env.VERCEL) {
  startServer(PORT);
}
