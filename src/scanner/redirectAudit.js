/**
 * Module d'audit des redirections HTTP → HTTPS
 * Vérifie que le site redirige correctement vers HTTPS et n'a pas de chaînes de redirection dangereuses.
 */

export async function auditRedirects(urlObj, timeoutMs = 6000) {
  const issues = [];
  const passed = [];
  const redirectChain = [];

  const hostname = urlObj.hostname;
  const httpUrl = `http://${hostname}${urlObj.port ? ':' + urlObj.port : ''}`;

  try {
    // Tester l'accès HTTP (port 80) avec redirect: 'manual' pour capturer la redirection
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(httpUrl, {
      method: 'HEAD',
      redirect: 'manual',
      signal: controller.signal,
      headers: { 'User-Agent': 'SecurScan/1.0 Security Auditor' }
    });

    clearTimeout(timer);

    const statusCode = res.status;
    const location = res.headers.get('location');

    redirectChain.push({
      url: httpUrl,
      status: statusCode,
      location: location || null
    });

    // Vérifier si HTTP redirige vers HTTPS
    if (statusCode >= 300 && statusCode < 400 && location) {
      if (/^https:\/\//i.test(location)) {
        // Bonne pratique : redirection HTTP → HTTPS
        if (statusCode === 301) {
          passed.push({
            code: 'HTTP_TO_HTTPS_301',
            title: 'Redirection HTTP → HTTPS permanente (301)',
            description: `Le serveur redirige correctement ${httpUrl} vers ${location} avec un code 301 (permanent).`
          });
        } else if (statusCode === 302 || statusCode === 307) {
          issues.push({
            code: 'HTTP_REDIRECT_TEMPORARY',
            title: 'Redirection HTTP → HTTPS temporaire au lieu de permanente',
            severity: 'LOW',
            cwe: 'CWE-311',
            cweTitle: 'Missing Encryption of Sensitive Data',
            description: `Le serveur redirige ${httpUrl} vers ${location} mais utilise un code ${statusCode} (temporaire) au lieu de 301 (permanent). Cela empêche le navigateur de mémoriser la redirection, exposant les utilisateurs à des interceptions sur la première requête.`,
            remediation: 'Utilisez un code 301 (Moved Permanently) pour la redirection HTTP → HTTPS afin que les navigateurs mémorisent la destination HTTPS.',
            snippet: `HTTP/${statusCode} → ${location} (devrait être 301)`
          });
        }

        // Vérifier si la redirection conserve le bon hostname
        try {
          const redirectTarget = new URL(location);
          if (redirectTarget.hostname !== hostname) {
            issues.push({
              code: 'HTTP_REDIRECT_DIFFERENT_HOST',
              title: 'Redirection HTTP vers un domaine différent',
              severity: 'MEDIUM',
              cwe: 'CWE-601',
              cweTitle: 'URL Redirection to Untrusted Site (Open Redirect)',
              description: `La redirection HTTP de ${hostname} pointe vers ${redirectTarget.hostname}. Cela peut indiquer une mauvaise configuration ou un détournement potentiel.`,
              remediation: 'Assurez-vous que la redirection HTTP pointe vers le même domaine en HTTPS.',
              snippet: `Location: ${location}`
            });
          }
        } catch (e) {
          // URL invalide dans location
        }
      } else {
        // Redirection HTTP → HTTP (pas vers HTTPS)
        issues.push({
          code: 'HTTP_NO_HTTPS_REDIRECT',
          title: 'Redirection HTTP ne pointe pas vers HTTPS',
          severity: 'HIGH',
          cwe: 'CWE-319',
          cweTitle: 'Cleartext Transmission of Sensitive Information',
          description: `La redirection depuis ${httpUrl} pointe vers ${location} qui n'est pas une URL HTTPS. Le trafic reste en clair et vulnérable aux interceptions MITM.`,
          remediation: 'Configurez la redirection pour pointer vers la version HTTPS de votre site.',
          snippet: `Location: ${location} (devrait commencer par https://)`
        });
      }
    } else if (statusCode >= 200 && statusCode < 300) {
      // Le site répond normalement en HTTP sans rediriger
      issues.push({
        code: 'HTTP_NO_REDIRECT',
        title: 'Site accessible en HTTP sans redirection vers HTTPS',
        severity: 'HIGH',
        cwe: 'CWE-319',
        cweTitle: 'Cleartext Transmission of Sensitive Information',
        description: `Le site ${httpUrl} répond avec un code ${statusCode} sans rediriger vers HTTPS. Le trafic peut transiter en clair, exposant les données utilisateur aux interceptions réseau (attaque Man-in-the-Middle).`,
        remediation: 'Configurez une redirection 301 de HTTP vers HTTPS dans votre serveur web (Nginx, Apache, etc.).',
        snippet: `HTTP ${statusCode} OK (pas de redirection HTTPS)`
      });
    }

  } catch (err) {
    // Le port 80 n'est pas accessible ou timeout
    if (err.name === 'AbortError') {
      passed.push({
        code: 'HTTP_PORT_CLOSED',
        title: 'Port HTTP (80) non accessible ou timeout',
        description: 'Le serveur ne répond pas sur le port 80 HTTP, ce qui empêche les connexions en clair.'
      });
    } else {
      // Connexion refusée ou autre erreur réseau
      passed.push({
        code: 'HTTP_CONNECTION_REFUSED',
        title: 'Port HTTP (80) fermé : connexion refusée',
        description: `Le port HTTP (80) est fermé ou inaccessible (${err.code || err.message}). Le site est accessible uniquement en HTTPS.`
      });
    }
  }

  return { issues, passed, redirectChain };
}
