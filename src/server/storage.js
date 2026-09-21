/**
 * Couche d'accès aux données (Storage) pour SecurScan
 */
import { db } from './db.js';
import { getThreatIntelligence } from '../scanner/threatIntelligence.js';

export function getOrCreateSite(targetUrl) {
  let urlObj;
  try {
    let u = targetUrl.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    urlObj = new URL(u);
  } catch (err) {
    throw new Error("URL invalide : " + err.message);
  }

  const hostname = urlObj.hostname;
  const canonicalUrl = `${urlObj.protocol}//${urlObj.host}`;

  const selectStmt = db.prepare('SELECT * FROM sites WHERE hostname = ?');
  const existing = selectStmt.get(hostname);

  if (existing) {
    return existing;
  }

  const siteId = 'site_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
  const now = new Date().toISOString();

  const insertStmt = db.prepare(`
    INSERT INTO sites (id, hostname, target_url, created_at, last_scanned_at, latest_score, latest_grade)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  insertStmt.run(siteId, hostname, canonicalUrl, now, null, 0, 'N/A');

  return {
    id: siteId,
    hostname,
    target_url: canonicalUrl,
    created_at: now,
    last_scanned_at: null,
    latest_score: 0,
    latest_grade: 'N/A'
  };
}

export function getLastScanForSite(siteId) {
  const stmt = db.prepare('SELECT * FROM scans WHERE site_id = ? ORDER BY timestamp DESC LIMIT 1');
  return stmt.get(siteId);
}

export function getScanById(scanId) {
  const stmt = db.prepare('SELECT * FROM scans WHERE id = ?');
  return stmt.get(scanId);
}

export function saveScan(siteId, report, regression) {
  const now = new Date().toISOString();
  const scanId = report.scanId || ('scan_' + Date.now());

  // 1. Sauvegarde du scan
  const insertScanStmt = db.prepare(`
    INSERT INTO scans (
      id, site_id, score, grade, verdict, duration_ms, timestamp, 
      passed_count, failed_count, regressions_count, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const regressionsCount = regression?.newIssues?.length || 0;
  insertScanStmt.run(
    scanId,
    siteId,
    report.score,
    report.grade,
    report.verdict,
    report.durationMs,
    now,
    report.stats?.passedChecks || 0,
    report.stats?.failedChecks || 0,
    regressionsCount,
    JSON.stringify(report)
  );

  // 2. Mise à jour du site
  const updateSiteStmt = db.prepare(`
    UPDATE sites 
    SET last_scanned_at = ?, latest_score = ?, latest_grade = ?
    WHERE id = ?
  `);
  updateSiteStmt.run(now, report.score, report.grade, siteId);

  // 3. Gestion des vulnérabilités (cycle de vie)
  const currentVulnCodes = new Set();

  for (const issue of report.vulnerabilities || []) {
    currentVulnCodes.add(issue.code);

    const findVulnStmt = db.prepare('SELECT * FROM vulnerabilities WHERE site_id = ? AND code = ?');
    const existing = findVulnStmt.get(siteId, issue.code);

    if (existing) {
      // Si la vulnérabilité était marquée RESOLVED mais revient, on la réouvre (Régression confirmée !)
      const newStatus = existing.status === 'RESOLVED' ? 'OPEN' : existing.status;
      const updateVulnStmt = db.prepare(`
        UPDATE vulnerabilities 
        SET scan_id = ?, last_seen_at = ?, status = ?, description = ?, remediation = ?, snippet = ?
        WHERE id = ?
      `);
      updateVulnStmt.run(
        scanId,
        now,
        newStatus,
        issue.description,
        issue.remediation,
        issue.snippet || '',
        existing.id
      );
    } else {
      const vulnId = 'vuln_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
      const insertVulnStmt = db.prepare(`
        INSERT INTO vulnerabilities (
          id, site_id, scan_id, code, title, severity, cwe, cwe_title,
          description, remediation, snippet, status, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)
      `);
      insertVulnStmt.run(
        vulnId,
        siteId,
        scanId,
        issue.code,
        issue.title,
        issue.severity,
        issue.cwe || 'CWE-Unknown',
        issue.cweTitle || 'Security Weakness',
        issue.description,
        issue.remediation,
        issue.snippet || '',
        now,
        now
      );
    }
  }

  // 4. Marquer comme RESOLVED les vulnérabilités qui ont disparu lors de ce scan
  const allSiteVulnsStmt = db.prepare("SELECT * FROM vulnerabilities WHERE site_id = ? AND status != 'RESOLVED'");
  const openVulns = allSiteVulnsStmt.all(siteId);

  for (const v of openVulns) {
    if (!currentVulnCodes.has(v.code)) {
      const resolveStmt = db.prepare("UPDATE vulnerabilities SET status = 'RESOLVED', resolved_at = ? WHERE id = ?");
      resolveStmt.run(now, v.id);
    }
  }

  return { scanId };
}

export function getAllSites() {
  const sitesStmt = db.prepare('SELECT * FROM sites ORDER BY last_scanned_at DESC');
  const sites = sitesStmt.all();

  return sites.map(site => {
    const vulnCountsStmt = db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM vulnerabilities 
      WHERE site_id = ? AND status IN ('OPEN', 'IN_PROGRESS')
      GROUP BY severity
    `);
    const counts = vulnCountsStmt.all(site.id);
    const severities = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const c of counts) {
      severities[c.severity] = c.count;
    }

    const scansCountStmt = db.prepare('SELECT COUNT(*) as count FROM scans WHERE site_id = ?');
    const scanCount = scansCountStmt.get(site.id)?.count || 0;

    const lastScanStmt = db.prepare('SELECT raw_json FROM scans WHERE site_id = ? ORDER BY timestamp DESC LIMIT 1');
    const lastScan = lastScanStmt.get(site.id);
    let techStack = [];
    if (lastScan?.raw_json) {
      try {
        const parsed = JSON.parse(lastScan.raw_json);
        techStack = parsed.techStack || [];
      } catch {}
    }

    return {
      ...site,
      scanCount,
      openIssues: severities,
      techStack
    };
  });
}

export function getSiteDetails(siteId) {
  const siteStmt = db.prepare('SELECT * FROM sites WHERE id = ?');
  const site = siteStmt.get(siteId);
  if (!site) return null;

  // Historique des 20 derniers scans
  const historyStmt = db.prepare(`
    SELECT id, score, grade, timestamp, duration_ms, regressions_count, passed_count, failed_count
    FROM scans 
    WHERE site_id = ? 
    ORDER BY timestamp ASC 
    LIMIT 20
  `);
  const history = historyStmt.all(siteId);

  // Toutes les vulnérabilités (avec statut et threat intelligence enrichie)
  const vulnsStmt = db.prepare(`
    SELECT * FROM vulnerabilities 
    WHERE site_id = ? 
    ORDER BY 
      CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
      END,
      last_seen_at DESC
  `);
  const rawVulns = vulnsStmt.all(siteId);
  const vulnerabilities = rawVulns.map(v => ({
    ...v,
    site_hostname: site.hostname,
    site_target_url: site.target_url,
    threatIntel: getThreatIntelligence(v.code, site.hostname)
  }));

  // Dernier scan complet
  const lastScan = getLastScanForSite(siteId);
  let lastReport = null;
  if (lastScan) {
    try {
      lastReport = JSON.parse(lastScan.raw_json);
      if (lastReport && lastReport.vulnerabilities) {
        lastReport.vulnerabilities.forEach(iv => {
          if (!iv.threatIntel) iv.threatIntel = getThreatIntelligence(iv.code, site.hostname);
        });
      }
    } catch {}
  }

  return {
    site,
    history,
    vulnerabilities,
    lastScanReport: lastReport
  };
}

export function getAllVulnerabilities({ severity, siteId, status } = {}) {
  let query = `
    SELECT v.*, 
           s.hostname as site_hostname, 
           s.target_url as site_target_url, 
           s.latest_grade as site_latest_grade, 
           s.latest_score as site_latest_score
    FROM vulnerabilities v
    JOIN sites s ON v.site_id = s.id
    WHERE 1=1
  `;
  const params = [];

  if (severity && severity !== 'ALL') {
    query += ` AND v.severity = ?`;
    params.push(severity);
  }
  if (siteId && siteId !== 'ALL') {
    query += ` AND v.site_id = ?`;
    params.push(siteId);
  }
  if (status && status !== 'ALL') {
    query += ` AND v.status = ?`;
    params.push(status);
  }

  query += ` ORDER BY 
    CASE v.severity
      WHEN 'CRITICAL' THEN 1
      WHEN 'HIGH' THEN 2
      WHEN 'MEDIUM' THEN 3
      WHEN 'LOW' THEN 4
      ELSE 5
    END,
    v.last_seen_at DESC`;

  const stmt = db.prepare(query);
  const rows = stmt.all(...params);

  return rows.map(r => ({
    ...r,
    threatIntel: getThreatIntelligence(r.code, r.site_hostname)
  }));
}

export function updateVulnerabilityStatus(vulnId, status) {
  const validStatuses = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'IGNORED'];
  if (!validStatuses.includes(status)) {
    throw new Error('Statut invalide : ' + status);
  }

  const stmt = db.prepare(`
    UPDATE vulnerabilities 
    SET status = ?, resolved_at = ? 
    WHERE id = ?
  `);
  const resolvedAt = status === 'RESOLVED' ? new Date().toISOString() : null;
  stmt.run(status, resolvedAt, vulnId);

  const getStmt = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?');
  return getStmt.get(vulnId);
}

export function resolveAllSiteVulnerabilities(siteId) {
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    UPDATE vulnerabilities 
    SET status = 'RESOLVED', resolved_at = ?
    WHERE site_id = ? AND status != 'RESOLVED'
  `);
  stmt.run(now, siteId);

  // Mettre à jour le score du site
  const updateSiteStmt = db.prepare(`
    UPDATE sites 
    SET latest_score = 95, latest_grade = 'A+'
    WHERE id = ?
  `);
  updateSiteStmt.run(siteId);

  return { success: true };
}

export function deleteSite(siteId) {
  // Suppression en cascade : vulnérabilités → scans → site
  db.prepare('DELETE FROM vulnerabilities WHERE site_id = ?').run(siteId);
  db.prepare('DELETE FROM scans WHERE site_id = ?').run(siteId);
  db.prepare('DELETE FROM sites WHERE id = ?').run(siteId);
  return { success: true };
}

export function getGlobalSummary() {
  const totalSites = db.prepare('SELECT COUNT(*) as count FROM sites').get()?.count || 0;
  const totalScans = db.prepare('SELECT COUNT(*) as count FROM scans').get()?.count || 0;
  
  const avgScoreRow = db.prepare('SELECT AVG(latest_score) as avgScore FROM sites WHERE last_scanned_at IS NOT NULL').get();
  const averageScore = avgScoreRow && avgScoreRow.avgScore !== null ? Math.round(avgScoreRow.avgScore) : 0;

  const vulnsCount = db.prepare(`
    SELECT severity, COUNT(*) as count 
    FROM vulnerabilities 
    WHERE status IN ('OPEN', 'IN_PROGRESS')
    GROUP BY severity
  `).all();

  const openVulnerabilities = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const v of vulnsCount) {
    openVulnerabilities[v.severity] = v.count;
  }

  return {
    totalSites,
    totalScans,
    averageScore,
    openVulnerabilities
  };
}
