/**
 * Module d'audit des en-têtes HTTP de sécurité
 */

export function auditHeaders(headers, urlObj) {
  const issues = [];
  const passed = [];
  const lowerHeaders = {};
  
  // Normaliser les en-têtes en minuscules
  for (const [key, value] of Object.entries(headers)) {
    lowerHeaders[key.toLowerCase()] = value;
  }

  // 1. Content-Security-Policy (CSP)
  const csp = lowerHeaders['content-security-policy'];
  if (!csp) {
    issues.push({
      code: 'MISSING_CSP',
      title: 'En-tête Content-Security-Policy (CSP) manquant',
      severity: 'HIGH',
      cwe: 'CWE-693',
      cweTitle: 'Protection Mechanism Failure',
      description: "Le site ne définit aucune politique de sécurité du contenu. Cela augmente considérablement le risque d'attaques par injection de script (XSS) et d'inclusion de ressources non autorisées.",
      remediation: "Ajoutez un en-tête Content-Security-Policy strict limitant les sources de scripts, styles et médias autorisés.",
      snippet: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    });
  } else {
    // Vérifier les faiblesses communes dans CSP
    const hasUnsafeInline = csp.includes("'unsafe-inline'");
    const hasUnsafeEval = csp.includes("'unsafe-eval'");

    if (hasUnsafeInline && !csp.includes('nonce-') && !csp.includes('sha256-')) {
      issues.push({
        code: 'CSP_UNSAFE_INLINE',
        title: "CSP permissive : utilisation de 'unsafe-inline'",
        severity: 'MEDIUM',
        cwe: 'CWE-79',
        cweTitle: 'Cross-Site Scripting (XSS)',
        description: "La directive CSP autorise 'unsafe-inline' sans nonces ou hachages, réduisant l'efficacité de la protection contre les injections XSS.",
        remediation: "Remplacez 'unsafe-inline' par des nonces cryptographiques (ex: 'nonce-...') ou des hachages (sha256).",
        snippet: "Content-Security-Policy: script-src 'self' 'nonce-rAnd0m123';"
      });
    }

    if (hasUnsafeEval) {
      issues.push({
        code: 'CSP_UNSAFE_EVAL',
        title: "CSP permissive : utilisation de 'unsafe-eval'",
        severity: 'MEDIUM',
        cwe: 'CWE-95',
        cweTitle: 'Improper Neutralization of Directives in Dynamically Evaluated Code',
        description: "L'instruction 'unsafe-eval' permet l'exécution de code via eval(), ce qui facilite l'exploitation de failles XSS.",
        remediation: "Éliminez l'usage de eval() ou Function() dans le code source et retirez 'unsafe-eval' de la CSP.",
        snippet: "Content-Security-Policy: script-src 'self';"
      });
    }

    passed.push({
      code: 'CSP_PRESENT',
      title: 'Content-Security-Policy configurée',
      value: csp.length > 80 ? csp.substring(0, 80) + '...' : csp
    });
  }

  // 2. Strict-Transport-Security (HSTS)
  const isHttps = urlObj.protocol === 'https:';
  const hsts = lowerHeaders['strict-transport-security'];
  if (isHttps) {
    if (!hsts) {
      issues.push({
        code: 'MISSING_HSTS',
        title: 'En-tête Strict-Transport-Security (HSTS) manquant',
        severity: 'HIGH',
        cwe: 'CWE-319',
        cweTitle: 'Cleartext Transmission of Sensitive Information',
        description: "Le navigateur n'est pas forcé d'utiliser exclusivement HTTPS. Les utilisateurs sont vulnérables aux attaques de rétrogradation SSL/TLS (SSL Stripping) et aux écoutes clandestines (MitM).",
        remediation: "Configurez l'en-tête HSTS avec une durée (max-age) minimale de 6 mois (15552000 secondes), idéalement 1 an.",
        snippet: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
      });
    } else {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 15552000) {
        issues.push({
          code: 'HSTS_SHORT_MAX_AGE',
          title: 'Durée HSTS max-age trop courte',
          severity: 'LOW',
          cwe: 'CWE-319',
          cweTitle: 'Cleartext Transmission of Sensitive Information',
          description: `La directive max-age actuelle est de ${maxAge} secondes (inférieure à 180 jours).`,
          remediation: "Augmentez le max-age à au moins 31536000 secondes (1 an).",
          snippet: "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        });
      }
      passed.push({
        code: 'HSTS_PRESENT',
        title: 'Strict-Transport-Security activé',
        value: hsts
      });
    }
  }

  // 3. X-Frame-Options (Clickjacking)
  const xfo = lowerHeaders['x-frame-options'];
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    issues.push({
      code: 'MISSING_X_FRAME_OPTIONS',
      title: 'Protection contre le Clickjacking manquante (X-Frame-Options / frame-ancestors)',
      severity: 'MEDIUM',
      cwe: 'CWE-1021',
      cweTitle: 'Improper Restriction of Rendered UI Layers or Frames',
      description: "Le site peut être intégré dans une iframe invisible sur un site malveillant pour intercepter les clics de l'utilisateur (Clickjacking / UI Redressing).",
      remediation: "Ajoutez l'en-tête X-Frame-Options avec la valeur DENY ou SAMEORIGIN, ou la directive CSP frame-ancestors.",
      snippet: "X-Frame-Options: DENY\n# Ou via CSP:\nContent-Security-Policy: frame-ancestors 'none';"
    });
  } else if (xfo) {
    passed.push({
      code: 'X_FRAME_OPTIONS_PRESENT',
      title: 'Protection Clickjacking configurée (X-Frame-Options)',
      value: xfo
    });
  }

  // 4. X-Content-Type-Options (MIME Sniffing)
  const xcto = lowerHeaders['x-content-type-options'];
  if (!xcto || xcto.toLowerCase().trim() !== 'nosniff') {
    issues.push({
      code: 'MISSING_X_CONTENT_TYPE_OPTIONS',
      title: "En-tête X-Content-Type-Options: nosniff manquant",
      severity: 'LOW',
      cwe: 'CWE-116',
      cweTitle: 'Improper Encoding or Escaping of Output',
      description: "Permet aux navigateurs d'effectuer du reniflage de type MIME (MIME-type sniffing), transformant des fichiers non exécutables (ex: images) en scripts malveillants.",
      remediation: "Ajoutez l'en-tête X-Content-Type-Options avec la valeur nosniff.",
      snippet: "X-Content-Type-Options: nosniff"
    });
  } else {
    passed.push({
      code: 'X_CONTENT_TYPE_OPTIONS_PRESENT',
      title: 'Protection MIME sniffing active',
      value: xcto
    });
  }

  // 5. Referrer-Policy
  const refPolicy = lowerHeaders['referrer-policy'];
  if (!refPolicy) {
    issues.push({
      code: 'MISSING_REFERRER_POLICY',
      title: 'En-tête Referrer-Policy manquant',
      severity: 'LOW',
      cwe: 'CWE-200',
      cweTitle: 'Exposure of Sensitive Information to an Unauthorized Actor',
      description: "Sans Referrer-Policy explicite, des URL complètes avec des paramètres sensibles (jetons, identifiants, emails) peuvent être transmises à des tiers dans l'en-tête Referer.",
      remediation: "Définissez Referrer-Policy à strict-origin-when-cross-origin ou no-referrer.",
      snippet: "Referrer-Policy: strict-origin-when-cross-origin"
    });
  } else {
    passed.push({
      code: 'REFERRER_POLICY_PRESENT',
      title: 'Referrer-Policy configurée',
      value: refPolicy
    });
  }

  // 6. Permissions-Policy (Feature-Policy)
  const permPolicy = lowerHeaders['permissions-policy'];
  if (!permPolicy) {
    issues.push({
      code: 'MISSING_PERMISSIONS_POLICY',
      title: 'En-tête Permissions-Policy manquant',
      severity: 'INFO',
      cwe: 'CWE-250',
      cweTitle: 'Execution with Unnecessary Privileges',
      description: "Permissions-Policy permet de restreindre l'accès aux fonctionnalités sensibles de l'appareil (caméra, microphone, géolocalisation, capteurs) pour la page et les iframes.",
      remediation: "Définissez les autorisations des APIs du navigateur.",
      snippet: "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
    });
  } else {
    passed.push({
      code: 'PERMISSIONS_POLICY_PRESENT',
      title: 'Permissions-Policy configurée',
      value: permPolicy
    });
  }

  // 7. Fuite d'informations (Server, X-Powered-By, X-AspNet-Version)
  const serverHeader = lowerHeaders['server'];
  const poweredBy = lowerHeaders['x-powered-by'];
  const aspNet = lowerHeaders['x-aspnet-version'];

  if (serverHeader && /[\d.]/.test(serverHeader)) {
    issues.push({
      code: 'SERVER_VERSION_LEAK',
      title: `Fuite de version du serveur web (${serverHeader})`,
      severity: 'LOW',
      cwe: 'CWE-200',
      cweTitle: 'Information Exposure',
      description: `L'en-tête Server révèle la version exacte du serveur web (${serverHeader}), facilitant la recherche d'exploits ciblés pour cette version spécifique.`,
      remediation: "Désactivez ou masquez la signature détaillée du serveur (ex: server_tokens off sous Nginx, ServerTokens Prod sous Apache).",
      snippet: "# Nginx:\nserver_tokens off;\n\n# Apache:\nServerSignature Off\nServerTokens Prod"
    });
  }

  if (poweredBy) {
    issues.push({
      code: 'X_POWERED_BY_LEAK',
      title: `En-tête X-Powered-By présent (${poweredBy})`,
      severity: 'LOW',
      cwe: 'CWE-200',
      cweTitle: 'Information Exposure',
      description: `L'en-tête X-Powered-By divulgue la technologie backend utilisée (${poweredBy}), ce qui aide les attaquants à cibler leurs vecteurs d'attaque.`,
      remediation: "Supprimez l'en-tête X-Powered-By dans la configuration de votre framework.",
      snippet: "// Express.js:\napp.disable('x-powered-by');\n\n# PHP (php.ini):\nexpose_php = Off"
    });
  }

  if (aspNet) {
    issues.push({
      code: 'X_ASPNET_LEAK',
      title: `En-tête X-AspNet-Version présent (${aspNet})`,
      severity: 'LOW',
      cwe: 'CWE-200',
      cweTitle: 'Information Exposure',
      description: "Divulgue la version d'ASP.NET utilisée.",
      remediation: "Désactivez l'attribut enableVersionHeader dans le web.config.",
      snippet: "<httpRuntime enableVersionHeader=\"false\" />"
    });
  }

  return { issues, passed };
}
