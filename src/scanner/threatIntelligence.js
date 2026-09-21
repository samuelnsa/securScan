/**
 * Module d'intelligence sur les menaces (Threat Modeling & Attack Scenarios)
 * Fournit une analyse approfondie des attaques potentielles et des données compromises
 * contextualisées selon le type de faille et la cible analysée.
 */

export function getThreatIntelligence(vulnCode, targetHostname = 'la cible') {
  const hostname = targetHostname || 'la cible';

  const threatCatalog = {
    // 1. CSP
    MISSING_CSP: {
      attackVectorTitle: "Injection de Scripts Malveillants & Cross-Site Scripting (XSS)",
      attackScenario: `1. L'attaquant identifie un point d'injection sur ${hostname} (paramètre d'URL, champ de formulaire, commentaire).\n2. En l'absence de Content-Security-Policy, le navigateur exécute aveuglément n'importe quel script JavaScript injecté ou chargé depuis un domaine tiers malveillant.\n3. Le script pirate capture en temps réel les frappes au clavier (keylogger) et intercepte les requêtes AJAX contenant des jetons d'autorisation.`,
      dataAtRisk: [
        "Cookies de session non protégés & jetons JWT (Session Hijacking)",
        "Identifiants de connexion et mots de passe saisis en temps réel",
        "Données personnelles et bancaires saisies dans les formulaires de paiement/profil",
        "Contenu confidentiel du DOM affiché à l'écran de la victime"
      ],
      businessImpact: [
        "Prise de contrôle des sessions utilisateurs (Account Takeover)",
        "Défacement de l'interface graphique de " + hostname + " ou redirection frauduleuse",
        "Exfiltration massive de données clients soumises au RGPD (Risque d'amendes CNIL)",
        "Atteinte critique à la réputation de marque et perte de confiance"
      ],
      attackerPrerequisites: "Possibilité d'injecter une charge utile (via un paramètre non filtré ou une dépendance tierce compromise)."
    },

    CSP_UNSAFE_INLINE: {
      attackVectorTitle: "Contournement de Politique CSP via Inline Scripting",
      attackScenario: `1. L'attaquant exploite la directive 'unsafe-inline' présente sur ${hostname}.\n2. Il injecte des balises <script> inline ou des attributs d'événements HTML (onload, onerror, onclick).\n3. La CSP n'exigeant ni hash SHA256 ni nonce cryptographique, le navigateur valide et exécute immédiatement le payload pirate.`,
      dataAtRisk: [
        "Jetons d'accès API (Bearer tokens)",
        "Données de formulaire en transit",
        "Historique de navigation et état applicatif de l'utilisateur"
      ],
      businessImpact: [
        "Exécution de transactions au nom de la victime",
        "Bypass partiel ou total des contrôles de sécurité applicatifs",
        "Modification non autorisée des paramètres utilisateur"
      ],
      attackerPrerequisites: "Présence d'un champ ou paramètre réfléchissant du HTML non assaini."
    },

    CSP_UNSAFE_EVAL: {
      attackVectorTitle: "Exécution Dynamique de Code JavaScript Arbitraire",
      attackScenario: `1. L'attaquant cible des fonctionnalités utilisant eval(), Function() ou setTimeout(string) sur ${hostname}.\n2. Grâce à 'unsafe-eval', il parvient à injecter une chaîne de caractères interprétée dynamiquement comme du code exécutable.\n3. Il contourne les filtres statiques et accède aux variables globales du scope JavaScript.`,
      dataAtRisk: [
        "Variables d'état React / Vue / Angular stockées en mémoire",
        "Clés de chiffrement client ou clés API publiques/privées résidant dans le runtime",
        "Jetons de rafraîchissement (Refresh Tokens)"
      ],
      businessImpact: [
        "Manipulation du flux logique de l'application",
        "Extraction de secrets applicatifs côté client"
      ],
      attackerPrerequisites: "Application utilisant des constructions d'évaluation de chaîne dynamique."
    },

    // 2. HSTS & SSL
    MISSING_HSTS: {
      attackVectorTitle: "Attaque Man-in-the-Middle (MitM) & Rétrogradation SSL Stripping",
      attackScenario: `1. La victime se connecte à un réseau non sécurisé (Wi-Fi public d'hôtel, aéroport, café).\n2. Un attaquant sur le même réseau utilise un outil comme sslstrip / ARP spoofing.\n3. Lorsque la victime tape "http://${hostname}" ou suit un lien non HTTPS, l'attaquant intercepte la requête avant qu'elle ne soit redirigée en HTTPS.\n4. L'attaquant maintient une liaison HTTP en clair avec la victime tout en négociant du HTTPS avec le serveur réel, agissant comme proxy transparent.`,
      dataAtRisk: [
        "Mots de passe et identifiants transmis en clair à chaque requête",
        "Cookies de session d'authentification sans chiffrement de transport",
        "Données bancaires, numéros de cartes de crédit et codes CVV",
        "Toutes les requêtes GET/POST transitant entre le navigateur et " + hostname
      ],
      businessImpact: [
        "Interception totale des flux sensibles en clair",
        "Usurpation d'identité immédiate et vol d'accès administrateur",
        "Non-conformité majeure aux exigences PCI-DSS et RGPD Article 32"
      ],
      attackerPrerequisites: "Position sur le chemin réseau de la victime (Wi-Fi public, routeur compromis, DNS menteur)."
    },

    HSTS_SHORT_MAX_AGE: {
      attackVectorTitle: "Expiration Rapide de la Protection HTTPS Forcée",
      attackScenario: `1. La directive max-age étant trop courte, la protection HSTS expire rapidement du cache du navigateur.\n2. Dès expiration, une requête ultérieure effectuée en HTTP redeviendra vulnérable aux attaques d'interception MitM avant toute renégociation.`,
      dataAtRisk: [
        "Requêtes initiales de reconnexion après expiration",
        "Paramètres d'authentification transmis lors d'une reconnexion froide"
      ],
      businessImpact: [
        "Fenêtre d'exposition périodique aux interceptions réseau"
      ],
      attackerPrerequisites: "Utilisateur se reconnectant après l'expiration du cache HSTS court."
    },

    // 3. Clickjacking / XFO
    MISSING_X_FRAME_OPTIONS: {
      attackVectorTitle: "Détournement de Clics (Clickjacking & UI Redressing)",
      attackScenario: `1. L'attaquant crée une page web piégée (ex: "Gagnez un iPhone") et intègre ${hostname} dans une <iframe> transparente positionnée au premier plan.\n2. Il superpose des boutons attrayants exactement au-dessus des boutons sensibles de ${hostname} (ex: "Supprimer mon compte", "Virement bancaire", "Autoriser l'application OAuth").\n3. La victime connectée à ${hostname} clique en croyant jouer, déclenchant en réalité une action irréversible à son insu.`,
      dataAtRisk: [
        "Autorisations OAuth et consentements de partage de données",
        "Actions administratives irréversibles (changement d'email, transfert de fonds)",
        "Validation de formulaires confidentiels à l'insu de l'utilisateur"
      ],
      businessImpact: [
        "Exécution involontaire d'actions privilégiées par des utilisateurs authentifiés",
        "Prise de contrôle de compte par changement d'adresse email ou de mot de passe",
        "Perte financière directe en cas de portails e-commerce ou bancaires"
      ],
      attackerPrerequisites: "Victime ayant une session active sur le site et visitant le site malveillant de l'attaquant."
    },

    // 4. MIME Sniffing
    MISSING_X_CONTENT_TYPE_OPTIONS: {
      attackVectorTitle: "Confusion de Type MIME & Exécution de Contenu Téléversé",
      attackScenario: `1. Un utilisateur téléverse sur ${hostname} un fichier image apparemment inoffensif (ex: avatar.jpg) contenant du code JavaScript malveillant dissimulé.\n2. En l'absence de 'X-Content-Type-Options: nosniff', le navigateur tente de deviner le type MIME réel (MIME Sniffing) et interprète le fichier comme du script ou du HTML exécutable.\n3. Le script s'exécute avec les privilèges de l'origine ${hostname}.`,
      dataAtRisk: [
        "Contexte de sécurité et cookies du domaine hôte",
        "Données privées d'autres utilisateurs consultant les fichiers téléversés"
      ],
      businessImpact: [
        "Élévation de privilèges via stockage d'artefacts exécutables",
        "Attaque XSS persistante via le CDN ou le stockage d'images de " + hostname
      ],
      attackerPrerequisites: "Présence d'un système d'upload de fichiers (images, documents, avatars)."
    },

    // 5. Referrer Policy
    MISSING_REFERRER_POLICY: {
      attackVectorTitle: "Fuite d'Informations Confidentielles via l'En-tête Referer",
      attackScenario: `1. ${hostname} utilise des URL contenant des tokens de réinitialisation de mot de passe, des identifiants de transaction ou des emails en paramètres GET (ex: /reset-password?token=secret123).\n2. Lorsque la victime clique sur un lien externe ou charge une image tierce, le navigateur transmet l'URL complète dans l'en-tête 'Referer'.\n3. Le serveur externe tiers ou l'attaquant récupère le jeton secret et l'utilise directement.`,
      dataAtRisk: [
        "Tokens de réinitialisation de mot de passe et liens magiques d'authentification",
        "Identifiants de commande, adresses email et paramètres de recherche internes",
        "Structure des routes d'administration internes"
      ],
      businessImpact: [
        "Compromission de comptes utilisateurs par vol de liens de réinitialisation",
        "Fuite de métadonnées sensibles vers des régies publicitaires ou services tiers"
      ],
      attackerPrerequisites: "Présence de paramètres sensibles dans les URL et de liens vers des domaines tiers."
    },

    // 6. Permissions Policy
    MISSING_PERMISSIONS_POLICY: {
      attackVectorTitle: "Accès Non Restreint aux API Matérielles Sensibles du Navigateur",
      attackScenario: `1. En cas d'intégration d'iframes tierces ou de scripts tiers (widgets, analytics) sur ${hostname}, ceux-ci peuvent solliciter l'accès aux capteurs de l'appareil (caméra, microphone, géolocalisation, USB).\n2. Sans Permissions-Policy pour désactiver ces fonctionnalités, un script tiers compromis peut tenter de collecter des données biométriques ou de géolocalisation de l'utilisateur.`,
      dataAtRisk: [
        "Coordonnées GPS précises de la victime",
        "Flux microphone / caméra (en cas de permissions pré-accordées)",
        "Données biométriques et capteurs de mouvement"
      ],
      businessImpact: [
        "Atteinte grave à la vie privée des utilisateurs",
        "Non-conformité avec les réglementations de protection des données"
      ],
      attackerPrerequisites: "Script tiers ou iframe malveillante présent sur la page."
    },

    // 7. Server & Tech Leaks
    SERVER_VERSION_LEAK: {
      attackVectorTitle: "Reconnaissance Ciblée & Exploitation de CVEs Serveur Connues",
      attackScenario: `1. L'attaquant envoie une simple requête HTTP à ${hostname} et lit l'en-tête 'Server' (ex: 'Apache/2.4.49' ou 'nginx/1.18.0').\n2. Il consulte les bases de données publiques de vulnérabilités (NVD, Exploit-DB, CVE) pour identifier des failles RCE (Remote Code Execution) ou Path Traversal spécifiques à cette version exacte.\n3. Il déploie un exploit automatisé ciblant spécifiquement cette version non patchée.`,
      dataAtRisk: [
        "Architecture système sous-jacente et système d'exploitation hôte",
        "Fichiers système et code source du serveur en cas d'exploit de version"
      ],
      businessImpact: [
        "Facilitation majeure des attaques automatisées de masse (Scanners de vulnérabilités)",
        "Risque accru de compromission totale de l'infrastructure hôte"
      ],
      attackerPrerequisites: "Accès réseau direct au serveur web."
    },

    X_POWERED_BY_LEAK: {
      attackVectorTitle: "Divulgation du Framework Applicatif & Ciblage Spécifique",
      attackScenario: `1. L'en-tête 'X-Powered-By' (ex: Express, PHP/7.4, Next.js, ASP.NET) révèle la technologie exacte motorisant ${hostname}.\n2. L'attaquant adapte ses vecteurs d'attaque (attaques de désérialisation PHP/Node, vulnérabilités de templates, injections spécifiques à la stack).`,
      dataAtRisk: [
        "Informations sur le middleware et la pile technologique interne",
        "Vulnérabilités de dépendances de bibliothèques tierces"
      ],
      businessImpact: [
        "Réduction drastique du temps nécessaire à un pirate pour cartographier et exploiter l'application"
      ],
      attackerPrerequisites: "Requête HTTP standard."
    },

    // 8. CORS
    CORS_WILDCARD_ALLOW_ORIGIN: {
      attackVectorTitle: "Exfiltration de Données Privées Cross-Origin (CORS Wildcard)",
      attackScenario: `1. L'API de ${hostname} renvoie 'Access-Control-Allow-Origin: *' ou autorise aveuglément les origines tierces avec transmission de credentials.\n2. L'attaquant attire un utilisateur authentifié sur un site malveillant (evil.com).\n3. Le script sur evil.com exécute un fetch() vers l'API de ${hostname} : le navigateur autorise la lecture de la réponse en raison de la configuration permissive.\n4. Les données privées de la victime sont transmises directement sur le serveur de l'attaquant.`,
      dataAtRisk: [
        "Données de profil confidentielles et historiques de commandes",
        "Messages privés, emails et documents stockés sur le compte",
        "Clés de sécurité internes et configurations d'organisation"
      ],
      businessImpact: [
        "Vol massif et automatisé de données privées d'utilisateurs connectés",
        "Violation flagrante du secret des correspondances et des données personnelles (RGPD)",
        "Piratage de comptes institutionnels et d'entreprises"
      ],
      attackerPrerequisites: "Victime authentifiée sur le site cible naviguant sur un site sous contrôle pirate."
    },

    CORS_ALLOW_ORIGIN_NULL: {
      attackVectorTitle: "Exploitation CORS via Origine 'null' (Sandboxed Iframes)",
      attackScenario: `1. La configuration CORS autorise l'origine 'null'.\n2. L'attaquant encapsule un script malveillant dans une iframe avec l'attribut sandbox (sans allow-same-origin), ce qui force le navigateur à envoyer 'Origin: null'.\n3. Le serveur de ${hostname} valide la requête et livre le contenu confidentiel à l'iframe pirate.`,
      dataAtRisk: [
        "Réponses d'API contenant des données personnelles",
        "Contenu d'endpoints sécurisés supposés privés"
      ],
      businessImpact: [
        "Bypass complet des restrictions de domaine CORS pour les attaques locales ou isolées"
      ],
      attackerPrerequisites: "Utilisateur consultant une page contenant une iframe isolée malveillante."
    },

    // 9. Cookies
    COOKIE_MISSING_SECURE: {
      attackVectorTitle: "Interception de Cookie en Clair sur Connexions HTTP",
      attackScenario: `1. Le cookie sur ${hostname} n'a pas l'attribut 'Secure'.\n2. Si l'utilisateur charge ne serait-ce qu'une seule ressource non chiffrée (ex: http://${hostname}/image.png ou redirection), le navigateur envoie le cookie en clair dans l'en-tête 'Cookie'.\n3. L'attaquant écoutant sur le réseau local (sniffing Wi-Fi) capture le cookie sans avoir à casser le chiffrement TLS.`,
      dataAtRisk: [
        "Cookie d'authentification et identifiant de session",
        "Jetons de tracking et préférences de sécurité utilisateur"
      ],
      businessImpact: [
        "Usurpation de session instantanée (Session Replay Attack)"
      ],
      attackerPrerequisites: "Écoute réseau passive sur un point d'accès non sécurisé."
    },

    COOKIE_MISSING_HTTPONLY: {
      attackVectorTitle: "Vol de Session par Script JavaScript (XSS Session Theft)",
      attackScenario: `1. En cas de faille XSS sur ${hostname}, le script injecté appelle document.cookie.\n2. L'absence de l'attribut 'HttpOnly' permet au script d'accéder au cookie d'authentification.\n3. Le script exfiltre le cookie vers un serveur de commande (C2) par une simple requête HTTP : l'attaquant clone la session sans connaître le mot de passe.`,
      dataAtRisk: [
        "Cookies de session administrateur / utilisateur",
        "Jetons JWT ou ID de sessions persistantes"
      ],
      businessImpact: [
        "Prise de contrôle totale du compte même avec une politique de mot de passe forte"
      ],
      attackerPrerequisites: "Présence d'une vulnérabilité XSS (Cross-Site Scripting) même mineure."
    },

    COOKIE_MISSING_SAMESITE: {
      attackVectorTitle: "Attaque par Falsification de Requête Inter-Sites (CSRF)",
      attackScenario: `1. Le cookie n'a pas d'attribut SameSite (ou est None).\n2. Un attaquant incite l'utilisateur connecté à visiter un site tiers piégé contenant un formulaire automatique pointant vers ${hostname}/api/transfer-funds ou /account/delete.\n3. Le navigateur inclut automatiquement les cookies d'authentification dans la requête, qui est exécutée avec succès par le serveur.`,
      dataAtRisk: [
        "Autorité de l'utilisateur sur son compte",
        "Ressources modifiables via des requêtes d'état (POST, PUT, DELETE)"
      ],
      businessImpact: [
        "Modifications frauduleuses de profil, changements de mot de passe ou virements bancaires forcés"
      ],
      attackerPrerequisites: "Victime authentifiée visitant une page conçue par l'attaquant."
    },

    // 10. Exposures
    EXPOSED_ENV_FILE: {
      attackVectorTitle: "Fuite Totale de Secrets d'Infrastructure & Clés Maîtresses (.env)",
      attackScenario: `1. L'attaquant envoie une requête GET sur https://${hostname}/.env.\n2. Le serveur web sert le fichier texte brut contenant l'ensemble des variables d'environnement de production.\n3. L'attaquant extrait les identifiants de base de données (DATABASE_URL), les clés API de passerelles de paiement (STRIPE_SECRET_KEY), les secrets de chiffrement JWT (APP_SECRET) et les clés de stockage cloud (AWS_SECRET_ACCESS_KEY).\n4. L'attaquant se connecte directement à la base de données distante ou vide les buckets S3 de l'entreprise.`,
      dataAtRisk: [
        "Mots de passe et chaînes de connexion directes à la Base de Données (PostgreSQL, MySQL, MongoDB)",
        "Clés d'API tierces avec privilèges financiers (Stripe, PayPal, SendGrid, Twilio)",
        "Secrets maîtres de signature JWT et clés privées de chiffrement d'application",
        "Identifiants de services Cloud (AWS, GCP, Azure, Cloudflare tokens)"
      ],
      businessImpact: [
        "Compromission TOTALE et immédiate de l'infrastructure et de l'ensemble des données",
        "Vidage ou rançonnage de la base de données client (Ransomware)",
        "Utilisation frauduleuse des comptes Cloud entraînant des coûts financiers massifs",
        "Révocation obligatoire de tous les secrets et arrêt d'urgence de la production"
      ],
      attackerPrerequisites: "Aucun prérequis. Requête HTTP GET publique directe."
    },

    EXPOSED_GIT_REPO: {
      attackVectorTitle: "Téléchargement Intégral du Code Source & Historique Git (.git)",
      attackScenario: `1. L'attaquant détecte que https://${hostname}/.git/ est accessible.\n2. À l'aide d'outils automatisés (GitTools, git-dumper), il télécharge l'arborescence des objets .git/.blob et reconstitue le dépôt Git complet en local.\n3. Il analyse l'intégralité du code source applicatif pour trouver des failles 0-day (injections SQL, logiques métier défaillantes) et fouille l'historique des commits à la recherche de clés API supprimées mais toujours valides.`,
      dataAtRisk: [
        "Intégralité du code source propriétaire de l'application",
        "Historique complet des commits avec adresses emails et commentaires des développeurs",
        "Secrets, tokens et mots de passe historiques oubliés dans d'anciens commits",
        "Schémas de base de données et logique métier interne"
      ],
      businessImpact: [
        "Vol de propriété intellectuelle industrielle",
        "Découverte accélérée de vulnérabilités critiques non publiques dans le code",
        "Compromission d'anciens secrets non révoqués"
      ],
      attackerPrerequisites: "Aucun prérequis. Requête HTTP GET publique directe."
    },

    // 11. SSL Certs & Redirects
    SSL_EXPIRED: {
      attackVectorTitle: "Rupture de Confiance Cryptographique & Interception Globale",
      attackScenario: `1. Le certificat SSL de ${hostname} est expiré.\n2. Les navigateurs affichent un avertissement de sécurité bloquant.\n3. Les attaquants peuvent forger des certificats frauduleux et intercepter les connexions des utilisateurs habitués à contourner les alertes.`,
      dataAtRisk: [
        "Intégrité des données en transit",
        "Toutes les communications chiffrées"
      ],
      businessImpact: [
        "Perte immédiate de 95% du trafic utilisateur (blocage navigateur)",
        "Chute du référencement SEO Google",
        "Risque élevé d'interception malveillante"
      ],
      attackerPrerequisites: "Certificat expiré."
    },

    NO_HTTPS_REDIRECT: {
      attackVectorTitle: "Persistance de Trafic Non Chiffré HTTP",
      attackScenario: `1. Lorsque l'utilisateur tape http://${hostname}, le serveur ne redirige pas automatiquement en code HTTP 301 vers https://${hostname}.\n2. L'utilisateur continue de naviguer sur la version HTTP non sécurisée.\n3. Tout le trafic reste en clair et accessible à toute écoute sur le réseau.`,
      dataAtRisk: [
        "Toutes les données transitant sur les pages HTTP non redirigées",
        "Identifiants de formulaires soumis sans chiffrement"
      ],
      businessImpact: [
        "Exposition continue au vol de données en transit",
        "Non-conformité standard de sécurité web"
      ],
      attackerPrerequisites: "Utilisateur accédant au site sans spécifier explicitement 'https://'."
    },

    NO_SSL_AVAILABLE: {
      attackVectorTitle: "Absence Totale de Chiffrement de Transport (Trafic en Clair)",
      attackScenario: `1. Le site ${hostname} ne dispose d'aucun certificat SSL/TLS valide.\n2. L'intégralité des requêtes et réponses circule en texte brut sur Internet (routeurs, FAI, points d'échange).\n3. N'importe quel équipement intermédiaire peut lire, enregistrer et altérer le contenu envoyé au client (injection de publicités ou malwares).`,
      dataAtRisk: [
        "Absolument toutes les données transmises (identifiants, messages, cookies)",
        "Intégrité du code HTML servi (risque de modification par injection réseau)"
      ],
      businessImpact: [
        "Non-respect des standards modernes de sécurité web",
        "Interdiction totale pour le traitement de données personnelles ou de paiement"
      ],
      attackerPrerequisites: "Aucun. Le trafic est public et non chiffré."
    }
  };

  // Valeur par défaut si le code n'est pas dans le catalogue
  const fallback = {
    attackVectorTitle: "Exploitation de Défaut de Configuration de Sécurité",
    attackScenario: `1. Un attaquant analyse les réponses réseau et configurations de ${hostname}.\n2. Il exploite cette anomalie pour contourner un mécanisme de défense ou glaner des métadonnées confidentielles.\n3. Il combine cette faiblesse avec d'autres vecteurs pour escalader ses privilèges sur la cible.`,
    dataAtRisk: [
      "Métadonnées de sécurité de l'application",
      "Données transitant sans protection adéquate",
      "Éléments d'authentification contextuels"
    ],
    businessImpact: [
      "Affaiblissement de la posture globale de cybersécurité",
      "Facilitation d'attaques en chaîne (Kill Chain)"
    ],
    attackerPrerequisites: "Accès réseau ou web standard."
  };

  return threatCatalog[vulnCode] || fallback;
}
