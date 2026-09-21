/**
 * Module d'audit de sécurité des Cookies
 */

export function auditCookies(rawCookies, isHttps = true) {
  const issues = [];
  const passed = [];

  if (!rawCookies) {
    return { issues, passed, totalCookies: 0 };
  }

  // Support array ou single string
  const cookieList = Array.isArray(rawCookies) ? rawCookies : [rawCookies];

  for (const cookieStr of cookieList) {
    const parts = cookieStr.split(';').map(p => p.trim());
    const [nameVal] = parts;
    const cookieName = nameVal.split('=')[0];

    const hasSecure = parts.some(p => p.toLowerCase() === 'secure');
    const hasHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
    const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));
    const sameSiteVal = sameSitePart ? sameSitePart.split('=')[1]?.toLowerCase() : null;

    // 1. Vérification du flag Secure
    if (!hasSecure && isHttps) {
      issues.push({
        code: 'COOKIE_MISSING_SECURE',
        title: `Cookie sans attribut 'Secure' (${cookieName})`,
        severity: 'MEDIUM',
        cwe: 'CWE-614',
        cweTitle: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
        description: `Le cookie '${cookieName}' n'a pas l'attribut 'Secure'. Il risque d'être transmis en clair sur des requêtes non chiffrées (attaque Man-in-the-Middle).`,
        remediation: "Ajoutez l'attribut 'Secure' à la directive Set-Cookie.",
        snippet: `Set-Cookie: ${cookieName}=...; Secure; HttpOnly; SameSite=Lax`
      });
    }

    // 2. Vérification du flag HttpOnly
    if (!hasHttpOnly) {
      // Si le nom suggère un cookie de session ou token
      const isLikelySession = /(session|token|auth|jwt|sid|id)/i.test(cookieName);
      issues.push({
        code: 'COOKIE_MISSING_HTTPONLY',
        title: `Cookie sans attribut 'HttpOnly' (${cookieName})`,
        severity: isLikelySession ? 'HIGH' : 'LOW',
        cwe: 'CWE-1004',
        cweTitle: 'Sensitive Cookie Without HttpOnly Flag',
        description: `Le cookie '${cookieName}' est accessible par du code JavaScript (document.cookie). En cas de vulnérabilité XSS, un attaquant peut dérober cette valeur.`,
        remediation: "Configurez l'attribut 'HttpOnly' pour bloquer l'accès depuis le DOM.",
        snippet: `Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Lax`
      });
    }

    // 3. Vérification de SameSite
    if (!sameSiteVal) {
      issues.push({
        code: 'COOKIE_MISSING_SAMESITE',
        title: `Cookie sans attribut 'SameSite' (${cookieName})`,
        severity: 'LOW',
        cwe: 'CWE-1275',
        cweTitle: 'Sensitive Cookie with Improper SameSite Attribute',
        description: `Le cookie '${cookieName}' ne spécifie pas d'attribut SameSite. Il est vulnérable aux attaques de type CSRF (Cross-Site Request Forgery).`,
        remediation: "Définissez SameSite=Lax ou SameSite=Strict selon l'usage.",
        snippet: `Set-Cookie: ${cookieName}=...; SameSite=Lax; Secure; HttpOnly`
      });
    } else if (sameSiteVal === 'none' && !hasSecure) {
      issues.push({
        code: 'COOKIE_SAMESITE_NONE_INSECURE',
        title: `Cookie 'SameSite=None' non sécurisé (${cookieName})`,
        severity: 'HIGH',
        cwe: 'CWE-1275',
        cweTitle: 'Sensitive Cookie with Improper SameSite Attribute',
        description: "Les navigateurs modernes rejettent les cookies configurés avec 'SameSite=None' qui ne possèdent pas l'attribut 'Secure'.",
        remediation: "Ajoutez l'attribut 'Secure' pour tout cookie SameSite=None.",
        snippet: `Set-Cookie: ${cookieName}=...; SameSite=None; Secure`
      });
    }

    if (hasSecure && hasHttpOnly && sameSiteVal) {
      passed.push({
        code: 'COOKIE_HARDENED',
        title: `Cookie '${cookieName}' bien sécurisé (Secure, HttpOnly, SameSite=${sameSiteVal})`,
        value: cookieName
      });
    }
  }

  return {
    issues,
    passed,
    totalCookies: cookieList.length
  };
}
