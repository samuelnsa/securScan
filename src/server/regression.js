/**
 * Moteur d'analyse des régressions et améliorations de sécurité entre les scans
 */

export function analyzeRegression(previousScan, currentReport) {
  if (!previousScan) {
    return {
      isInitialScan: true,
      hasRegression: false,
      scoreDiff: 0,
      newIssues: [],
      resolvedIssues: [],
      alerts: []
    };
  }

  let prevReport = null;
  try {
    prevReport = JSON.parse(previousScan.raw_json);
  } catch {
    prevReport = null;
  }

  if (!prevReport) {
    return {
      isInitialScan: false,
      hasRegression: false,
      scoreDiff: 0,
      newIssues: [],
      resolvedIssues: [],
      alerts: []
    };
  }

  const prevCodes = new Set((prevReport.vulnerabilities || []).map(v => v.code));
  const currentCodes = new Set((currentReport.vulnerabilities || []).map(v => v.code));

  // 1. Nouvelles vulnérabilités apparues (RÉGRESSION)
  const newIssues = (currentReport.vulnerabilities || []).filter(v => !prevCodes.has(v.code));

  // 2. Vulnérabilités résolues (AMÉLIORATION)
  const resolvedIssues = (prevReport.vulnerabilities || []).filter(v => !currentCodes.has(v.code));

  // 3. Différence de score
  const scoreDiff = currentReport.score - prevReport.score;

  // 4. Génération des alertes
  const alerts = [];

  if (scoreDiff < 0) {
    alerts.push({
      type: 'SCORE_DROP',
      level: 'WARNING',
      message: `Baisse du score de sécurité de ${Math.abs(scoreDiff)} point(s) (de ${prevReport.score}/100 à ${currentReport.score}/100)`
    });
  } else if (scoreDiff > 0) {
    alerts.push({
      type: 'SCORE_RISE',
      level: 'SUCCESS',
      message: `Amélioration du score de sécurité : +${scoreDiff} point(s) (de ${prevReport.score}/100 à ${currentReport.score}/100)`
    });
  }

  if (newIssues.length > 0) {
    const criticalNew = newIssues.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH');
    alerts.push({
      type: 'NEW_VULNERABILITIES',
      level: criticalNew.length > 0 ? 'DANGER' : 'WARNING',
      message: `${newIssues.length} nouvelle(s) vulnérabilité(s) détectée(s) : ${newIssues.map(i => i.title).join(', ')}`
    });
  }

  if (resolvedIssues.length > 0) {
    alerts.push({
      type: 'RESOLVED_VULNERABILITIES',
      level: 'SUCCESS',
      message: `${resolvedIssues.length} vulnérabilité(s) corrigée(s) avec succès : ${resolvedIssues.map(i => i.title).join(', ')}`
    });
  }

  // Alerte SSL
  if (currentReport.ssl && prevReport.ssl) {
    if (currentReport.ssl.daysRemaining <= 30 && prevReport.ssl.daysRemaining > 30) {
      alerts.push({
        type: 'SSL_EXPIRING',
        level: 'WARNING',
        message: `Attention : le certificat SSL expire désormais dans moins de 30 jours (${currentReport.ssl.daysRemaining} j restant(s)).`
      });
    }
  }

  const hasRegression = scoreDiff < 0 || newIssues.length > 0;

  return {
    isInitialScan: false,
    hasRegression,
    scoreDiff,
    newIssues,
    resolvedIssues,
    alerts
  };
}
