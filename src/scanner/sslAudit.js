/**
 * Module d'audit SSL/TLS et inspection des certificats X.509
 */
import tls from 'node:tls';

export function auditSSL(hostname, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const issues = [];
    const passed = [];

    const socket = tls.connect(
      {
        host: hostname,
        port: port,
        servername: hostname, // Support SNI
        rejectUnauthorized: false, // Permet d'inspecter même si auto-signé ou expiré
        timeout: timeoutMs
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();
          const isAuthorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!cert || Object.keys(cert).length === 0) {
            issues.push({
              code: 'NO_CERTIFICATE',
              title: 'Aucun certificat SSL/TLS renvoyé',
              severity: 'CRITICAL',
              cwe: 'CWE-295',
              cweTitle: 'Improper Certificate Validation',
              description: "Le serveur n'a présenté aucun certificat SSL/TLS valide lors de la négociation.",
              remediation: "Installez un certificat SSL/TLS valide émis par une autorité de certification reconnue (ex: Let's Encrypt).",
              snippet: "# Utilisez certbot pour obtenir un certificat gratuit:\ncertbot --nginx -d " + hostname
            });

            socket.destroy();
            return resolve({
              hasSsl: false,
              issues,
              passed,
              details: null
            });
          }

          // 1. Vérification de la validation de confiance de l'autorité
          if (!isAuthorized) {
            issues.push({
              code: 'SSL_UNTRUSTED_CERTIFICATE',
              title: `Certificat non approuvé (${authError || 'Chaîne invalide'})`,
              severity: 'HIGH',
              cwe: 'CWE-295',
              cweTitle: 'Improper Certificate Validation',
              description: `Le certificat SSL présenté n'est pas approuvé par les autorités de confiance : ${authError}. Les navigateurs afficheront un écran d'alerte rouge bloquant.`,
              remediation: "Remplacez le certificat auto-signé ou intermédiaire manquant par un certificat valide émis par une CA reconnue.",
              snippet: "certbot renew --force-renewal"
            });
          } else {
            passed.push({
              code: 'SSL_TRUSTED',
              title: 'Certificat SSL/TLS approuvé par une autorité reconnue',
              value: cert.issuer?.O || cert.issuer?.CN || 'CA Reconnue'
            });
          }

          // 2. Vérification des dates de validité
          const validTo = new Date(cert.valid_to);
          const validFrom = new Date(cert.valid_from);
          const now = new Date();
          const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          if (now > validTo) {
            issues.push({
              code: 'SSL_EXPIRED',
              title: `Certificat SSL/TLS expiré (depuis ${Math.abs(daysRemaining)} jours)`,
              severity: 'CRITICAL',
              cwe: 'CWE-298',
              cweTitle: 'Improper Validation of Certificate Expiration',
              description: `Le certificat a expiré le ${validTo.toISOString().split('T')[0]}. Toutes les connexions sécurisées sont compromises ou rejetées par les clients.`,
              remediation: "Renouvelez immédiatement votre certificat SSL/TLS.",
              snippet: "certbot renew"
            });
          } else if (daysRemaining <= 14) {
            issues.push({
              code: 'SSL_EXPIRING_VERY_SOON',
              title: `Certificat SSL/TLS expire très bientôt (${daysRemaining} jours restants)`,
              severity: 'HIGH',
              cwe: 'CWE-298',
              cweTitle: 'Improper Validation of Certificate Expiration',
              description: `Le certificat expirera le ${validTo.toISOString().split('T')[0]}. Risque imminent d'interruption de service.`,
              remediation: "Renouvelez le certificat sans attendre.",
              snippet: "certbot renew"
            });
          } else if (daysRemaining <= 30) {
            issues.push({
              code: 'SSL_EXPIRING_SOON',
              title: `Certificat SSL/TLS expire dans moins d'un mois (${daysRemaining} jours restants)`,
              severity: 'MEDIUM',
              cwe: 'CWE-298',
              cweTitle: 'Improper Validation of Certificate Expiration',
              description: `Le certificat expirera le ${validTo.toISOString().split('T')[0]}. Pensez à planifier ou automatiser son renouvellement.`,
              remediation: "Vérifiez que le renouvellement automatique (cron / systemd timer) est actif.",
              snippet: "certbot renew --dry-run"
            });
          } else {
            passed.push({
              code: 'SSL_VALIDITY',
              title: `Validité du certificat optimale (${daysRemaining} jours restants)`,
              value: `Expire le ${validTo.toLocaleDateString('fr-FR')}`
            });
          }

          // 3. Vérification de la version TLS
          if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
            issues.push({
              code: 'INSECURE_TLS_VERSION',
              title: `Version TLS obsolète négociée (${protocol})`,
              severity: 'HIGH',
              cwe: 'CWE-326',
              cweTitle: 'Inadequate Encryption Strength',
              description: `Les protocoles TLS 1.0 et 1.1 sont officiellement dépréciés (RFC 8996) en raison de vulnérabilités cryptographiques connues (BEAST, POODLE).`,
              remediation: "Configurez votre serveur pour n'accepter que TLS 1.2 et TLS 1.3.",
              snippet: "# Nginx:\nssl_protocols TLSv1.2 TLSv1.3;\n\n# Apache:\nSSLProtocol -all +TLSv1.2 +TLSv1.3"
            });
          } else {
            passed.push({
              code: 'TLS_VERSION_SECURE',
              title: `Protocole TLS moderne (${protocol})`,
              value: protocol
            });
          }

          // Détails du certificat
          const details = {
            subject: cert.subject?.CN || hostname,
            issuer: cert.issuer?.O || cert.issuer?.CN || 'Inconnu',
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining,
            protocol,
            cipher: cipher ? `${cipher.name} (${cipher.version})` : 'Inconnu',
            san: cert.subjectaltname ? cert.subjectaltname.split(', ') : [],
            authorized: isAuthorized,
            serialNumber: cert.serialNumber
          };

          socket.destroy();
          resolve({
            hasSsl: true,
            issues,
            passed,
            details
          });
        } catch (err) {
          socket.destroy();
          resolve({
            hasSsl: false,
            issues: [{
              code: 'SSL_PARSE_ERROR',
              title: "Erreur d'analyse du certificat SSL",
              severity: 'MEDIUM',
              cwe: 'CWE-295',
              cweTitle: 'Improper Certificate Validation',
              description: err.message,
              remediation: "Vérifiez la configuration SSL du serveur web.",
              snippet: ""
            }],
            passed: [],
            details: null
          });
        }
      }
    );

    socket.on('error', (err) => {
      socket.destroy();
      resolve({
        hasSsl: false,
        issues: [{
          code: 'SSL_CONNECTION_FAILED',
          title: "Échec de connexion SSL/TLS sur le port " + port,
          severity: 'HIGH',
          cwe: 'CWE-319',
          cweTitle: 'Cleartext Transmission of Sensitive Information',
          description: `Impossible d'établir une négociation TLS avec ${hostname}:${port} (${err.message}). Le site n'est probablement pas disponible en HTTPS.`,
          remediation: "Activez HTTPS sur votre serveur web avec un certificat TLS valide.",
          snippet: "certbot --nginx -d " + hostname
        }],
        passed: [],
        details: null
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        hasSsl: false,
        issues: [{
          code: 'SSL_TIMEOUT',
          title: "Délai d'attente dépassé lors de la connexion SSL/TLS",
          severity: 'MEDIUM',
          cwe: 'CWE-400',
          cweTitle: 'Uncontrolled Resource Consumption',
          description: `La connexion TLS à ${hostname}:${port} a expiré après ${timeoutMs}ms.`,
          remediation: "Vérifiez que le port 443 est ouvert dans votre pare-feu.",
          snippet: "sudo ufw allow 443/tcp"
        }],
        passed: [],
        details: null
      });
    });
  });
}
