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

// 5c. Export HTML d'un rapport de scan
app.get('/api/sites/:id/export', (req, res) => {
  try {
    const details = getSiteDetails(req.params.id);
    if (!details) return res.status(404).json({ error: 'Site introuvable.' });

    const report = details.lastScanReport;
    const site = details.site;
    const vulns = details.vulnerabilities || [];

    const html = generateExportHTML(site, report, vulns, details.history);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="securscan-report-${site.hostname}.html"`);
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
function generateExportHTML(site, report, vulns, history) {
  const sevColors = { CRITICAL: '#ff0055', HIGH: '#f97316', MEDIUM: '#ffb703', LOW: '#4facfe', INFO: '#94a3b8' };

  const vulnRows = vulns.map(v => `
    <tr>
      <td><span style="color: ${sevColors[v.severity] || '#fff'}; font-weight: 600;">${v.severity}</span></td>
      <td>${v.title}</td>
      <td style="font-family: monospace; font-size: 0.85rem;">${v.cwe || '-'}</td>
      <td><span style="padding: 2px 8px; border-radius: 4px; background: ${v.status === 'RESOLVED' ? 'rgba(0,255,135,0.15)' : v.status === 'OPEN' ? 'rgba(255,0,85,0.15)' : 'rgba(255,183,3,0.15)'}; color: ${v.status === 'RESOLVED' ? '#00ff87' : v.status === 'OPEN' ? '#ff0055' : '#ffb703'};">${v.status}</span></td>
      <td style="max-width: 350px; font-size: 0.85rem;">${v.remediation || '-'}</td>
    </tr>
  `).join('');

  const historyRows = (history || []).map(h => `
    <tr>
      <td>${new Date(h.timestamp).toLocaleDateString('fr-FR')}</td>
      <td><strong>${h.grade}</strong></td>
      <td>${h.score}/100</td>
      <td>${h.passed_count || 0} ✓ / ${h.failed_count || 0} ✗</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecurScan – Rapport d'Audit : ${site.hostname}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0a0e1a; color: #f1f5f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 2rem; line-height: 1.6; }
    .container { max-width: 960px; margin: 0 auto; }
    h1 { font-size: 1.8rem; color: #00f2fe; margin-bottom: 0.5rem; }
    h2 { font-size: 1.3rem; color: #00f2fe; margin: 2rem 0 1rem; border-bottom: 1px solid rgba(0,242,254,0.2); padding-bottom: 0.5rem; }
    .meta { color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }
    .score-box { display: flex; align-items: center; gap: 2rem; background: rgba(11,17,29,0.8); border: 1px solid rgba(0,242,254,0.2); border-radius: 12px; padding: 1.5rem 2rem; margin: 1.5rem 0; }
    .score-grade { font-size: 3rem; font-weight: 900; color: #00ff87; }
    .score-number { font-size: 2rem; font-family: monospace; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 0.9rem; }
    th { color: #00f2fe; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.06); color: #526079; font-size: 0.8rem; text-align: center; }
    .tech-chip { display: inline-block; padding: 3px 10px; background: rgba(0,242,254,0.1); border: 1px solid rgba(0,242,254,0.2); border-radius: 20px; font-size: 0.8rem; margin: 3px; }
    @media print { body { background: #fff; color: #111; } th { color: #0066cc; } .score-box { border-color: #ccc; background: #f9f9f9; } .score-grade { color: #28a745; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ SECURSCAN – Rapport d'Audit de Sécurité</h1>
    <p class="meta">
      Cible : <strong>${site.hostname}</strong> (${site.target_url})<br>
      Généré le : ${new Date().toLocaleDateString('fr-FR')} à ${new Date().toLocaleTimeString('fr-FR')}<br>
      Nombre total de scans : ${history ? history.length : 0}
    </p>

    <div class="score-box">
      <div class="score-grade">${site.latest_grade}</div>
      <div>
        <div class="score-number">${site.latest_score}/100</div>
        <div style="color: #94a3b8;">${report?.verdict || 'Analyse effectuée'}</div>
      </div>
    </div>

    ${report?.techStack && report.techStack.length > 0 ? `
      <h2>🔍 Technologies Détectées</h2>
      <div>${report.techStack.map(t => `<span class="tech-chip">${t.icon} ${t.name} (${t.category})</span>`).join('')}</div>
    ` : ''}

    <h2>⚠️ Vulnérabilités Détectées (${vulns.length})</h2>
    ${vulns.length > 0 ? `
      <table>
        <thead><tr><th>Sévérité</th><th>Titre</th><th>CWE</th><th>Statut</th><th>Remédiation</th></tr></thead>
        <tbody>${vulnRows}</tbody>
      </table>
    ` : '<p style="color: #00ff87;">✅ Aucune vulnérabilité détectée. Excellent !</p>'}

    ${history && history.length > 0 ? `
      <h2>📊 Historique des Scans</h2>
      <table>
        <thead><tr><th>Date</th><th>Note</th><th>Score</th><th>Checks</th></tr></thead>
        <tbody>${historyRows}</tbody>
      </table>
    ` : ''}

    ${report?.ssl ? `
      <h2>🔒 Certificat SSL/TLS</h2>
      <table>
        <tbody>
          <tr><td>Émetteur</td><td>${report.ssl.issuer}</td></tr>
          <tr><td>Protocole</td><td>${report.ssl.protocol} (${report.ssl.cipher})</td></tr>
          <tr><td>Expiration</td><td>${new Date(report.ssl.validTo).toLocaleDateString('fr-FR')} (${report.ssl.daysRemaining} jours restants)</td></tr>
          <tr><td>Chaîne CA</td><td>${report.ssl.authorized ? 'Approuvée ✓' : 'Non approuvée ✗'}</td></tr>
        </tbody>
      </table>
    ` : ''}

    <div class="footer">
      <p>Rapport généré par SecurScan v2.0 // Autonomous Cyber-Audit & Defense Board</p>
      <p>Conforme OWASP Top 10 & CWE | Données auditées de manière passive (aucun test intrusif)</p>
    </div>
  </div>
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

// Démarrage du serveur avec gestion dynamique du port
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

startServer(PORT);
