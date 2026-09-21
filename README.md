# 🛡️ SecurScan Pro — Suite d'Audit de Sécurité Web, DAST & Auto-Hardening Studio

**SecurScan Pro** est une plateforme complète et autonome d'audit passif de sécurité web (DAST), de surveillance des applications et de remédiation automatisée. Elle cartographie les vulnérabilités (OWASP & CWE), modélise les vecteurs d'attaque et les données compromises pour chaque site, détecte les régressions de sécurité et génère des patchs de durcissement multi-stacks prêts à déployer.

---

## 🌟 Fonctionnalités Clés

### 1. 🔍 Moteur d'Audit Passif Multi-Couches (DAST)
* **En-têtes HTTP de Sécurité** :
  * `Content-Security-Policy` (CSP) : Détection d'absence ou de directives permissives (`unsafe-inline`, `unsafe-eval`).
  * `Strict-Transport-Security` (HSTS) : Chiffrement HTTPS forcé, max-age, sous-domaines et preload.
  * `X-Frame-Options` & `frame-ancestors` : Protection anti-Clickjacking / UI Redressing.
  * `X-Content-Type-Options` : Blocage du MIME-sniffing (`nosniff`).
  * `Referrer-Policy` : Prévention des fuites d'identifiants et jetons sensibles en URL.
  * `Permissions-Policy` : Contrôle des accès matériels (caméra, microphone, géolocalisation).
  * `Fuites d'Informations` : Détection de divulgation de version logicielle (`Server`, `X-Powered-By`).
* **Inspection SSL / TLS & Certificats X.509** :
  * Validité temporelle, jours restants avec alertes d'expiration (< 30j et < 14j).
  * Négociation TLS 1.3/1.2 et détection de protocoles obsolètes.
  * Chaîne de confiance et autorité de certification (CA).
* **Sécurité des Cookies** :
  * Attributs `HttpOnly` (anti-vol de session XSS), `Secure` (HTTPS) et `SameSite` (Lax/Strict contre le CSRF).
* **Détection Passive d'Exposition** :
  * Fichiers `.env` et dépôts `.git/HEAD` exposés publiquement.
  * Standard de divulgation responsable `/.well-known/security.txt` (RFC 9116).
* **Audit des Politiques CORS** :
  * Détection des origines sauvages (`*` ou `null`) avec credentials.

### 2. ⚡ Analyse Approfondie des Menaces (Threat Modeling & Attack Scenarios)
* **Scénario d'attaque chronologique** étape par étape pour chaque vulnérabilité et pour chaque site hôte.
* **Inventaire des données et actifs compromis** : Tokens JWT, mots de passe de base de données, cookies de session, données personnelles RGPD/PII, clés API privées (AWS, Stripe).
* **Impact métier et conformité** : Évaluation du risque de prise de contrôle (Account Takeover), dégradation de réputation, défacement, sanctions CNIL/RGPD.

### 3. 🛠️ Auto-Hardening Studio Multi-Stack (1 Clic)
* Génération instantanée de snippets et patchs complets de configuration :
  * 🌐 **Nginx** (`.conf`)
  * 🪶 **Apache** (`.htaccess`)
  * 🟢 **Express.js** (`helmet.js` / middleware)
  * ▲ **Next.js** (`next.config.js`)
  * 🔒 **Caddy** (`Caddyfile`)
  * ▲ **Vercel** (`vercel.json`)
* Sécurisation globale en 1 clic ou sécurisation granulaire faille par faille.

### 4. 🗂️ Centre de Remédiation avec Classification par Site
* Attribution explicite de chaque vulnérabilité à son site hôte avec saut direct en 1 clic.
* Filtrage par site (`Tous les sites`, `site1.com`, `site2.com`...) et par niveau de sévérité (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* Double mode d'affichage : **🗂️ Classé par Site** et **📋 Liste Globale**.

### 5. 🌐 Pages Détaillées Dédiées par Site
* Accès instantané en 1 clic depuis le Bento Dashboard.
* Empreintes technologiques détectées, certificat SSL/TLS, courbe d'évolution des notes et liste complète des solutions assignées.
* Export de rapports autonomes HTML et JSON.

### 6. 📉 Détection Automatisée de Régressions & Diff Comparatif
* Suivi dans **SQLite local** (`data/securscan.db`).
* Comparaison de posture scan $N$ vs $N-1$ avec alertes visuelles immédiates.
* Comparateur différentiel interactif entre deux audits quelconques.

---

## 🚀 Démarrage Rapide

### Prérequis
* [Node.js](https://nodejs.org/) v18+ (recommandé v20 ou v22).

### Lancer l'Application Web
```bash
npm run dev
```
Ouvrez votre navigateur sur : **[http://localhost:3000](http://localhost:3000)** *(ou le port alloué affiché dans le terminal)*.

---

## 💻 Utilisation en Ligne de Commande (CLI)

```bash
# Audit instantané d'une cible
npm run scan https://example.com

# Audit avec export JSON automatique
npm run scan https://example.com -- --json rapport.json
```

---

## 📡 Endpoints API REST

| Méthode | Route | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan` | Déclenche un audit passif, analyse les régressions et enregistre le scan |
| `GET` | `/api/summary` | Télémétrie globale (total sites, scans, score moyen, failles ouvertes) |
| `GET` | `/api/sites` | Liste des services monitorés avec scores et statistiques |
| `GET` | `/api/sites/:id` | Fiche complète du site, historique des scores et vulnérabilités |
| `DELETE` | `/api/sites/:id` | Supprime un service monitoré et son historique |
| `GET` | `/api/vulnerabilities` | Liste globale des failles avec attribution site et threat modeling |
| `PATCH` | `/api/vulnerabilities/:id` | Met à jour le statut (`OPEN`, `IN_PROGRESS`, `RESOLVED`, `IGNORED`) |
| `GET` | `/api/sites/:id/patch` | Génère le patch de durcissement multi-stack pour ce site |
| `POST` | `/api/patch/generate` | Génère un patch personnalisé à partir d'une liste de failles |
| `GET` | `/api/scans/:id1/compare/:id2` | Calcule le différentiel entre deux scans |
| `GET` | `/api/sites/:id/export` | Télécharge le rapport HTML autonome |

---

## 🛡️ Structure du Projet

```
hackerr/
├── data/                    # Base de données SQLite locale (securscan.db - gitignore)
├── src/
│   ├── scanner/             # Moteur d'audit passif (DAST)
│   │   ├── headersAudit.js  # Audit des en-têtes HTTP de sécurité
│   │   ├── sslAudit.js      # Inspection SSL/TLS & certificats X.509
│   │   ├── cookieAudit.js   # Audit des flags de cookies (HttpOnly, Secure, SameSite)
│   │   ├── corsAudit.js     # Audit des politiques Cross-Origin
│   │   ├── exposureAudit.js # Audit d'exposition passive (.env, .git, security.txt)
│   │   ├── redirectAudit.js # Audit de la chaîne de redirection HTTP -> HTTPS
│   │   ├── techDetect.js    # Fingerprinting technologique passif
│   │   ├── threatIntelligence.js # Modélisation approfondie des menaces & scénarios
│   │   ├── scorer.js        # Algorithme de notation (A+ à F) et mapping CWE
│   │   └── index.js         # Moteur de scan principal & interface CLI
│   ├── server/              # Backend Express & persistance SQLite
│   │   ├── db.js            # Schémas et initialisation SQLite native
│   │   ├── regression.js    # Analyseur de régressions et alertes
│   │   ├── patchGenerator.js # Générateur de patchs multi-stack (Nginx, Apache, Express, Next, Caddy, Vercel)
│   │   ├── storage.js       # Couche d'accès aux données & cycle de vie
│   │   └── index.js         # Serveur API REST & fichiers statiques
│   └── client/              # Dashboard Cyber-Neobrutalism (Neoflux)
│       ├── index.html       # Structure HTML & composants Bento
│       ├── styles.css       # Design System Neoflux, ombres dures & accents cyber-web
│       └── app.js           # Gestionnaire d'état, routage hash, remédiation & visualisations
├── .gitignore
├── package.json
└── README.md
```

---

## 📄 Licence
Ce projet est sous licence ISC.
