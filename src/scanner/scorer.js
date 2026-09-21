/**
 * Module de calcul du score de sécurité et classification
 */

const SEVERITY_WEIGHTS = {
  CRITICAL: 35,
  HIGH: 20,
  MEDIUM: 10,
  LOW: 5,
  INFO: 0
};

export function calculateScore(issues, passed) {
  let score = 100;
  let hasCritical = false;
  let hasHigh = false;

  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  };

  for (const issue of issues) {
    const sev = (issue.severity || 'LOW').toUpperCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;

    const penalty = SEVERITY_WEIGHTS[sev] ?? 5;
    score -= penalty;

    if (sev === 'CRITICAL') hasCritical = true;
    if (sev === 'HIGH') hasHigh = true;
  }

  // Ne pas descendre en-dessous de 0
  score = Math.max(0, score);

  // Plafonnement en cas de failles sévères
  if (hasCritical) {
    score = Math.min(score, 30); // Faille critique = note F directe
  }

  // Détermination de la note (Grade)
  let grade = 'F';
  if (score >= 95 && !hasHigh && !hasCritical) {
    grade = 'A+';
  } else if (score >= 85 && !hasCritical) {
    grade = 'A';
  } else if (score >= 70 && !hasCritical) {
    grade = 'B';
  } else if (score >= 50 && !hasCritical) {
    grade = 'C';
  } else if (score >= 35) {
    grade = 'D';
  } else {
    grade = 'F';
  }

  // Évaluation textuelle
  let verdict = '';
  if (grade === 'A+' || grade === 'A') {
    verdict = 'Excellent niveau de durcissement de sécurité. Les standards modernes sont respectés.';
  } else if (grade === 'B') {
    verdict = 'Bon niveau global, mais quelques en-têtes et directives méritent d\'être renforcés.';
  } else if (grade === 'C') {
    verdict = 'Niveau de sécurité moyen. Des protections fondamentales font défaut (CSP, Clickjacking...).';
  } else if (grade === 'D') {
    verdict = 'Sécurité vulnérable. Des lacunes majeures exposent le site à des attaques.';
  } else {
    verdict = 'Critique : Vulnérabilités sévères ou absence totale de configuration de sécurité.';
  }

  return {
    score,
    grade,
    verdict,
    stats: {
      totalChecks: issues.length + passed.length,
      passedChecks: passed.length,
      failedChecks: issues.length,
      severities: severityCounts
    }
  };
}
