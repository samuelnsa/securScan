/**
 * Moteur principal de scan passif et interface CLI
 */
import { auditHeaders } from './headersAudit.js';
import { auditSSL } from './sslAudit.js';
import { auditCookies } from './cookieAudit.js';
import { auditExposure } from './exposureAudit.js';
import { auditCORS } from './corsAudit.js';
import { detectTechnologies } from './techDetect.js';
import { auditRedirects } from './redirectAudit.js';
import { calculateScore } from './scorer.js';
import { getThreatIntelligence } from './threatIntelligence.js';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

/**
 * Exécute un scan passif complet sur une cible
 * @param {string} rawUrl - URL ou nom de domaine
 * @param {object} options - Options de scan
 * @returns {Promise<object>} Rapport de sécurité complet
 */
export async function scanTarget(rawUrl, options = {}) {
  const startTime = Date.now();
  
  // Normaliser l'URL
  let targetUrl = rawUrl.trim();
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = 'https://' + targetUrl;
  }

  const urlObj = new URL(targetUrl);
  const isHttps = urlObj.protocol === 'https:';

  const allIssues = [];
  const allPassed = [];
  let responseData = null;
  let sslData = null;
  let techStack = [];
  let redirectData = null;

  // 1. Audit Réseau & HTTP Headers
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeout || 10000);

    const res = await fetch(urlObj.toString(), {
      method: 'GET',
      headers: {
        'User-Agent': 'SecurScan/1.0 (+https://github.com/security-audit)'
      },
      redirect: 'follow',
      signal: controller.signal
    });

    clearTimeout(timeout);

    // Extraction des en-têtes
    const headersObj = {};
    for (const [key, value] of res.headers.entries()) {
      headersObj[key] = value;
    }

    // Récupération des cookies
    const rawCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : res.headers.get('set-cookie');

    responseData = {
      statusCode: res.status,
      statusText: res.statusText,
      finalUrl: res.url,
      headers: headersObj
    };

    // Audit des en-têtes HTTP
    const headerResult = auditHeaders(headersObj, new URL(res.url));
    allIssues.push(...headerResult.issues);
    allPassed.push(...headerResult.passed);

    // Audit des cookies
    const cookieResult = auditCookies(rawCookies, isHttps);
    allIssues.push(...cookieResult.issues);
    allPassed.push(...cookieResult.passed);

    // Audit CORS (Cross-Origin Resource Sharing)
    const corsResult = auditCORS(headersObj);
    allIssues.push(...corsResult.issues);
    allPassed.push(...corsResult.passed);

    // Détection de technologies (fingerprinting passif)
    techStack = detectTechnologies(headersObj, rawCookies);

  } catch (err) {
    allIssues.push({
      code: 'HTTP_FETCH_FAILED',
      title: "Échec de connexion HTTP/HTTPS à l'hôte",
      severity: 'CRITICAL',
      cwe: 'CWE-319',
      cweTitle: 'Cleartext Transmission of Sensitive Information',
      description: `Impossible de contacter la cible : ${err.message}`,
      remediation: "Vérifiez que l'URL est accessible et que le serveur web est démarré.",
      snippet: ""
    });
  }

  // 2. Audit SSL/TLS
  if (isHttps) {
    const port = urlObj.port ? parseInt(urlObj.port, 10) : 443;
    sslData = await auditSSL(urlObj.hostname, port, options.sslTimeout || 8000);
    allIssues.push(...sslData.issues);
    allPassed.push(...sslData.passed);
  } else {
    allIssues.push({
      code: 'NO_HTTPS_CONFIGURED',
      title: 'Site accessible uniquement en HTTP non chiffré',
      severity: 'CRITICAL',
      cwe: 'CWE-319',
      cweTitle: 'Cleartext Transmission of Sensitive Information',
      description: "Le site utilise le protocole HTTP en clair. Toutes les données échangées (mots de passe, sessions) peuvent être interceptées.",
      remediation: "Installez un certificat SSL/TLS et redirigez tout le trafic vers HTTPS.",
      snippet: "# Redirection Nginx:\nserver {\n    listen 80;\n    server_name " + urlObj.hostname + ";\n    return 301 https://$host$request_uri;\n}"
    });
  }

  // 3. Audit passif d'exposition (.env, .git, etc.)
  if (options.checkExposure !== false) {
    const exposureResult = await auditExposure(urlObj.origin);
    allIssues.push(...exposureResult.issues);
    allPassed.push(...exposureResult.passed);
  }

  // 4. Audit des redirections HTTP → HTTPS
  if (isHttps && options.checkRedirects !== false) {
    try {
      redirectData = await auditRedirects(urlObj);
      allIssues.push(...redirectData.issues);
      allPassed.push(...redirectData.passed);
    } catch (e) {
      // Silently skip redirect audit if network issue
    }
  }

  // Trier les vulnérabilités par ordre de gravité et attacher l'intelligence sur les menaces
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  allIssues.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));
  allIssues.forEach(issue => {
    issue.threatIntel = getThreatIntelligence(issue.code, urlObj.hostname);
  });

  // 4. Calcul du score et de la note finale
  const scoreResult = calculateScore(allIssues, allPassed);
  const durationMs = Date.now() - startTime;

  // 6. Assemblage du rapport final JSON
  const report = {
    scanId: 'scan_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    target: {
      inputUrl: rawUrl,
      resolvedUrl: responseData?.finalUrl || targetUrl,
      hostname: urlObj.hostname,
      protocol: urlObj.protocol.replace(':', ''),
      statusCode: responseData?.statusCode || null
    },
    timestamp: new Date().toISOString(),
    durationMs,
    score: scoreResult.score,
    grade: scoreResult.grade,
    verdict: scoreResult.verdict,
    stats: scoreResult.stats,
    ssl: sslData?.details || null,
    techStack: techStack || [],
    redirectChain: redirectData?.redirectChain || [],
    vulnerabilities: allIssues,
    passedChecks: allPassed
  };

  return report;
}

// Support exécution directe CLI
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const targetArg = args[0];

  if (!targetArg || targetArg === '--help' || targetArg === '-h') {
    console.log(`
🛡️ SecurScan CLI - Outil d'Audit Passif & Détection de Vulnérabilités Web

Usage :
  node src/scanner/index.js <URL> [options]

Options :
  --json [fichier]   Sauvegarder le rapport complet au format JSON
  --help, -h         Afficher cette aide

Exemples :
  node src/scanner/index.js https://example.com
  node src/scanner/index.js https://monsite.fr --json rapport-monsite.json
    `);
    process.exit(0);
  }

  console.log(`\n🔍 Lancement du scan de sécurité sur : ${targetArg} ...`);

  scanTarget(targetArg)
    .then((report) => {
      console.log(`\n======================================================`);
      console.log(`  RÉSULTATS DE L'AUDIT : ${report.target.hostname}`);
      console.log(`======================================================`);
      console.log(`Note globale : [ ${report.grade} ] (Score : ${report.score}/100)`);
      console.log(`Statut       : ${report.verdict}`);
      console.log(`Durée        : ${report.durationMs} ms`);
      console.log(`Checks       : ${report.stats.passedChecks} OK / ${report.stats.failedChecks} alertes`);
      console.log(`Détail       : 🔴 ${report.stats.severities.CRITICAL} Critique(s) | 🟠 ${report.stats.severities.HIGH} Élevée(s) | 🟡 ${report.stats.severities.MEDIUM} Moyenne(s) | 🔵 ${report.stats.severities.LOW} Faible(s)`);

      if (report.ssl) {
        console.log(`\n🔒 SSL/TLS :`);
        console.log(`  - Émetteur : ${report.ssl.issuer}`);
        console.log(`  - Protocole: ${report.ssl.protocol} (${report.ssl.cipher})`);
        console.log(`  - Expiration : dans ${report.ssl.daysRemaining} jours (${report.ssl.validTo.split('T')[0]})`);
      }

      if (report.vulnerabilities.length > 0) {
        console.log(`\n⚠️  LISTE DES VULNÉRABILITÉS DÉTECTÉES :`);
        report.vulnerabilities.forEach((v, idx) => {
          const badge = {
            CRITICAL: '🔴 [CRITIQUE]',
            HIGH: '🟠 [ÉLEVÉE]  ',
            MEDIUM: '🟡 [MOYENNE] ',
            LOW: '🔵 [FAIBLE]  ',
            INFO: 'ℹ️  [INFO]    '
          }[v.severity] || '[ALERTE]';

          console.log(`\n${idx + 1}. ${badge} ${v.title} (${v.cwe})`);
          console.log(`   Description : ${v.description}`);
          console.log(`   Remédiation : ${v.remediation}`);
        });
      } else {
        console.log(`\n✅ Aucune vulnérabilité passive détectée ! Excellent travail.`);
      }

      // Enregistrement JSON optionnel
      const jsonIdx = args.indexOf('--json');
      if (jsonIdx !== -1) {
        const outFile = args[jsonIdx + 1] && !args[jsonIdx + 1].startsWith('-') 
          ? args[jsonIdx + 1] 
          : `report-${report.target.hostname}.json`;
        fs.writeFileSync(outFile, JSON.stringify(report, null, 2), 'utf8');
        console.log(`\n📁 Rapport JSON complet exporté avec succès dans : ${outFile}`);
      }

      console.log(`\n======================================================\n`);
    })
    .catch((err) => {
      console.error('\n❌ Erreur fatale pendant le scan :', err.message);
      process.exit(1);
    });
}
