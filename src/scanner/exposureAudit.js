/**
 * Module d'audit passif d'exposition de fichiers sensibles et bonnes pratiques
 */

export async function auditExposure(baseUrl, timeoutMs = 5000) {
  const issues = [];
  const passed = [];

  const checks = [
    {
      path: '/.env',
      code: 'EXPOSED_ENV_FILE',
      title: 'Fichier .env exposé publiquement',
      severity: 'CRITICAL',
      cwe: 'CWE-552',
      cweTitle: 'Files or Directories Accessible to External Parties',
      description: "Le fichier de variables d'environnement .env est accessible publiquement. Il contient très probablement des secrets critiques (mots de passe BDD, clés API privées, tokens JWT).",
      remediation: "Interdisez immédiatement l'accès aux fichiers cachés dans la configuration de votre serveur web et déplacez les fichiers sensibles hors du dossier web root.",
      snippet: "# Nginx:\nlocation ~ /\\.env {\n    deny all;\n    return 404;\n}\n\n# Apache (.htaccess):\n<Files \".env\">\n    Require all denied\n</Files>",
      validator: (text, contentType) => {
        if (contentType && contentType.includes('text/html')) return false; // Évite les faux positifs des pages 404 personnalisées
        return /(DB_PASSWORD|DATABASE_URL|API_KEY|APP_SECRET|AWS_SECRET|PORT=|NODE_ENV=)/i.test(text);
      }
    },
    {
      path: '/.git/HEAD',
      code: 'EXPOSED_GIT_REPO',
      title: 'Dossier .git accessible publiquement',
      severity: 'CRITICAL',
      cwe: 'CWE-552',
      cweTitle: 'Files or Directories Accessible to External Parties',
      description: "Le répertoire Git est exposé. Un attaquant peut télécharger l'intégralité du code source, l'historique des commits, et les secrets passés de votre application.",
      remediation: "Bloquez l'accès aux répertoires .git au niveau du serveur web ou du reverse proxy.",
      snippet: "# Nginx:\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}\n\n# Apache:\nRedirectMatch 404 /\\.git",
      validator: (text) => text.trim().startsWith('ref: refs/')
    },
    {
      path: '/robots.txt',
      code: 'ROBOTS_TXT_CHECK',
      title: 'Fichier robots.txt',
      severity: 'INFO',
      cwe: 'CWE-200',
      cweTitle: 'Information Exposure',
      description: "Le fichier robots.txt peut lister des chemins d'administration ou dossiers internes sensibles.",
      remediation: "Vérifiez que robots.txt ne révèle pas de routes secrètes sensibles.",
      snippet: "User-agent: *\nDisallow: /admin/",
      isInformational: true
    },
    {
      path: '/.well-known/security.txt',
      code: 'SECURITY_TXT_CHECK',
      title: 'Fichier standard security.txt (RFC 9116)',
      severity: 'INFO',
      cwe: 'CWE-1059',
      cweTitle: 'Incomplete Documentation',
      description: "Le fichier standard security.txt permet aux chercheurs en sécurité de contacter rapidement vos équipes en cas de faille découverte.",
      remediation: "Créez un fichier /.well-known/security.txt avec votre email de contact et votre clé PGP.",
      snippet: "Contact: mailto:security@votre-domaine.com\nExpires: 2027-12-31T23:59:59.000Z",
      isBestPractice: true
    }
  ];

  for (const check of checks) {
    try {
      const targetUrl = new URL(check.path, baseUrl).toString();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const response = await fetch(targetUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'SecurScan/1.0 (+https://github.com/security-audit)'
        },
        signal: controller.signal
      });

      clearTimeout(timer);

      if (response.status === 200) {
        const text = await response.text();
        const contentType = response.headers.get('content-type') || '';

        if (check.validator) {
          if (check.validator(text, contentType)) {
            issues.push({
              code: check.code,
              title: check.title,
              severity: check.severity,
              cwe: check.cwe,
              cweTitle: check.cweTitle,
              description: check.description,
              remediation: check.remediation,
              snippet: check.snippet,
              proof: text.substring(0, 150)
            });
          } else {
            passed.push({
              code: `${check.code}_PROTECTED`,
              title: `Protection active pour ${check.path}`,
              value: 'Non accessible publiquement'
            });
          }
        } else if (check.isBestPractice) {
          if (text.includes('Contact:')) {
            passed.push({
              code: 'SECURITY_TXT_PRESENT',
              title: 'Standard security.txt (RFC 9116) implémenté',
              value: 'Présent et valide'
            });
          } else {
            issues.push({
              code: 'MISSING_SECURITY_TXT',
              title: 'Fichier security.txt (RFC 9116) absent ou incomplet',
              severity: 'INFO',
              cwe: 'CWE-1059',
              cweTitle: 'Incomplete Documentation',
              description: check.description,
              remediation: check.remediation,
              snippet: check.snippet
            });
          }
        } else if (check.isInformational) {
          passed.push({
            code: 'ROBOTS_TXT_PRESENT',
            title: 'Fichier robots.txt accessible',
            value: `Taille: ${text.length} caractères`
          });
        }
      } else {
        if (!check.isBestPractice && !check.isInformational) {
          passed.push({
            code: `${check.code}_SECURE`,
            title: `Ressource ${check.path} inaccessible (Code HTTP ${response.status})`,
            value: `Sécurisé (HTTP ${response.status})`
          });
        } else if (check.isBestPractice) {
          issues.push({
            code: 'MISSING_SECURITY_TXT',
            title: 'Fichier standard security.txt (RFC 9116) absent',
            severity: 'INFO',
            cwe: 'CWE-1059',
            cweTitle: 'Incomplete Documentation',
            description: check.description,
            remediation: check.remediation,
            snippet: check.snippet
          });
        }
      }
    } catch {
      // Ignorer les erreurs de réseau sur les sondes passives de fichiers
    }
  }

  return { issues, passed };
}
