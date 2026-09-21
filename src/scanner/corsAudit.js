/**
 * Module d'audit CORS (Cross-Origin Resource Sharing)
 * Détecte les configurations CORS permissives ou dangereuses.
 */

export function auditCORS(headers) {
  const issues = [];
  const passed = [];
  const lowerHeaders = {};

  for (const [key, val] of Object.entries(headers)) {
    lowerHeaders[key.toLowerCase()] = val;
  }

  const acao = lowerHeaders['access-control-allow-origin'];
  const acac = lowerHeaders['access-control-allow-credentials'];
  const acam = lowerHeaders['access-control-allow-methods'];
  const acah = lowerHeaders['access-control-allow-headers'];
  const aceh = lowerHeaders['access-control-expose-headers'];

  // 1. Vérification wildcard ACAO avec credentials
  if (acao === '*') {
    if (acac && acac.toLowerCase() === 'true') {
      issues.push({
        code: 'CORS_WILDCARD_WITH_CREDENTIALS',
        title: 'CORS : Wildcard (*) avec credentials activés',
        severity: 'CRITICAL',
        cwe: 'CWE-942',
        cweTitle: 'Permissive Cross-domain Policy with Untrusted Domains',
        description: 'La politique CORS autorise tous les origines (*) tout en permettant l\'envoi de cookies/credentials. Cela permet à n\'importe quel site tiers de faire des requêtes authentifiées en tant que l\'utilisateur, ce qui ouvre la voie à des attaques de vol de session et d\'exfiltration de données.',
        remediation: 'Remplacez Access-Control-Allow-Origin: * par une liste blanche d\'origines autorisés (ex: https://mon-app.com). Ne jamais combiner wildcard et credentials.',
        snippet: `Access-Control-Allow-Origin: * (DANGEREUX)\nAccess-Control-Allow-Credentials: true`
      });
    } else {
      issues.push({
        code: 'CORS_WILDCARD_ORIGIN',
        title: 'CORS : Wildcard (*) permissif détecté',
        severity: 'MEDIUM',
        cwe: 'CWE-942',
        cweTitle: 'Permissive Cross-domain Policy with Untrusted Domains',
        description: 'La politique CORS autorise tous les origines (*). Bien que les credentials ne soient pas activés, cela expose les réponses API à tout domaine tiers, facilitant l\'enumération ou le scraping de données.',
        remediation: 'Limitez Access-Control-Allow-Origin à vos domaines de confiance explicites plutôt que le wildcard.',
        snippet: `Access-Control-Allow-Origin: *`
      });
    }
  } else if (acao) {
    // Vérification : est-ce que l'origin est reflétée dynamiquement (potentiel problème) ?
    // On ne peut pas tester cela passivement, mais on le note comme point d'attention
    passed.push({
      code: 'CORS_ORIGIN_RESTRICTED',
      title: 'CORS : Origine restreinte correctement configurée',
      description: `Access-Control-Allow-Origin: ${acao}`
    });
  }

  // 2. Vérification des méthodes dangereuses exposées
  if (acam) {
    const methods = acam.split(',').map(m => m.trim().toUpperCase());
    const dangerousMethods = methods.filter(m => ['DELETE', 'PUT', 'PATCH'].includes(m));

    if (dangerousMethods.length > 0 && acao === '*') {
      issues.push({
        code: 'CORS_DANGEROUS_METHODS_EXPOSED',
        title: `CORS : Méthodes dangereuses exposées (${dangerousMethods.join(', ')})`,
        severity: 'HIGH',
        cwe: 'CWE-749',
        cweTitle: 'Exposed Dangerous Method or Function',
        description: `Les méthodes HTTP ${dangerousMethods.join(', ')} sont autorisées en cross-origin avec un wildcard, ce qui permet à des sites tiers d'exécuter des opérations destructives (suppression, modification) sur vos ressources.`,
        remediation: 'Restreignez les méthodes CORS aux méthodes strictement nécessaires (GET, POST) et limitez l\'origine.',
        snippet: `Access-Control-Allow-Methods: ${acam}`
      });
    } else if (dangerousMethods.length > 0) {
      passed.push({
        code: 'CORS_METHODS_RESTRICTED',
        title: 'CORS : Méthodes sensibles avec origine restreinte',
        description: `Méthodes ${dangerousMethods.join(', ')} exposées mais avec origine restreinte.`
      });
    }
  }

  // 3. Vérification des en-têtes exposés sensibles
  if (aceh) {
    const exposedHeaders = aceh.split(',').map(h => h.trim().toLowerCase());
    const sensitiveHeaders = exposedHeaders.filter(h => 
      ['authorization', 'set-cookie', 'x-api-key', 'x-csrf-token'].includes(h)
    );

    if (sensitiveHeaders.length > 0) {
      issues.push({
        code: 'CORS_SENSITIVE_HEADERS_EXPOSED',
        title: `CORS : En-têtes sensibles exposés en cross-origin`,
        severity: 'HIGH',
        cwe: 'CWE-200',
        cweTitle: 'Exposure of Sensitive Information to an Unauthorized Actor',
        description: `Les en-têtes ${sensitiveHeaders.join(', ')} sont exposés via Access-Control-Expose-Headers, permettant à des origines tiers de lire ces données sensibles.`,
        remediation: 'Retirez les en-têtes sensibles (Authorization, Set-Cookie) de Access-Control-Expose-Headers.',
        snippet: `Access-Control-Expose-Headers: ${aceh}`
      });
    }
  }

  // 4. Absence de CORS = pas de problème cross-origin explicite (comportement par défaut sécurisé)
  if (!acao && !acam && !acah) {
    passed.push({
      code: 'CORS_NOT_CONFIGURED',
      title: 'CORS : Pas de politique cross-origin explicite (restrictif par défaut)',
      description: 'Le serveur ne définit pas d\'en-têtes CORS, ce qui empêche les requêtes cross-origin par défaut (Same-Origin Policy active).'
    });
  }

  return { issues, passed };
}
