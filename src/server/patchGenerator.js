/**
 * Moteur de génération de patches de sécurisation complets et individuels
 * Supporte : Nginx, Apache, Express.js, Next.js, Caddy, Vercel
 */

export function generateHardeningPatch(vulnerabilities, stack = 'nginx', hostname = 'example.com') {
  const codes = new Set(vulnerabilities.map(v => v.code));
  
  // Directives recommandées selon les failles détectées
  const hasCsp = codes.has('MISSING_CSP') || codes.has('CSP_UNSAFE_INLINE');
  const hasHsts = codes.has('MISSING_HSTS') || codes.has('HSTS_SHORT_MAX_AGE');
  const hasXfo = codes.has('MISSING_X_FRAME_OPTIONS');
  const hasXcto = codes.has('MISSING_X_CONTENT_TYPE_OPTIONS');
  const hasRef = codes.has('MISSING_REFERRER_POLICY');
  const hasPerm = codes.has('MISSING_PERMISSIONS_POLICY');
  const hasServerLeak = codes.has('SERVER_VERSION_LEAK') || codes.has('X_POWERED_BY_LEAK');
  const hasEnvLeak = codes.has('EXPOSED_ENV_FILE');
  const hasGitLeak = codes.has('EXPOSED_GIT_REPO');
  const hasCookieFix = vulnerabilities.some(v => v.code.startsWith('COOKIE_'));
  const hasCorsFix = codes.has('CORS_WILDCARD_ALLOW_ORIGIN') || codes.has('CORS_ALLOW_ORIGIN_NULL') || codes.has('CORS_EXPOSED_HEADERS');
  const hasRedirectFix = codes.has('NO_HTTPS_REDIRECT') || codes.has('HTTP_REDIRECT_CHAIN_TOO_LONG');

  switch (stack.toLowerCase()) {
    case 'nginx':
      return generateNginxPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasServerLeak, hasEnvLeak, hasGitLeak, hasCorsFix, hasRedirectFix, hostname });
    case 'apache':
      return generateApachePatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasServerLeak, hasEnvLeak, hasGitLeak, hasCorsFix, hasRedirectFix });
    case 'express':
      return generateExpressPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasServerLeak, hasCookieFix, hasCorsFix });
    case 'nextjs':
      return generateNextjsPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasCorsFix });
    case 'caddy':
      return generateCaddyPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasCorsFix, hasRedirectFix, hostname });
    case 'vercel':
      return generateVercelPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasCorsFix });
    default:
      return generateNginxPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasServerLeak, hasEnvLeak, hasGitLeak, hasCorsFix, hasRedirectFix, hostname });
  }
}

function generateNginxPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasServerLeak, hasEnvLeak, hasGitLeak, hasCorsFix, hasRedirectFix, hostname }) {
  let conf = `# ==============================================================================
# 🛡️ SECURSCAN AUTO-HARDENING PATCH POUR NGINX
# Cible : ${hostname} | Date : ${new Date().toISOString().split('T')[0]}
# À inclure dans votre bloc server { ... } (ex: /etc/nginx/conf.d/${hostname}.conf)
# ==============================================================================

`;

  if (hasRedirectFix) {
    conf += `# 1. Redirection automatique HTTP vers HTTPS (301 Permanent)
server {
    listen 80;
    listen [::]:80;
    server_name ${hostname};
    return 301 https://$host$request_uri;
}

`;
  }

  if (hasServerLeak) {
    conf += `# 2. Masquer la version de Nginx (Anti-fuite Server header)
server_tokens off;

`;
  }

  conf += `# 3. Injection des En-têtes HTTP de Sécurité
`;
  if (hasHsts) {
    conf += `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n`;
  }
  if (hasXfo) {
    conf += `add_header X-Frame-Options "DENY" always;\n`;
  }
  if (hasXcto) {
    conf += `add_header X-Content-Type-Options "nosniff" always;\n`;
  }
  if (hasRef) {
    conf += `add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n`;
  }
  if (hasPerm) {
    conf += `add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;\n`;
  }
  if (hasCsp) {
    conf += `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none';" always;\n`;
  }

  if (hasCorsFix) {
    conf += `
# 4. Politique CORS restreinte (Remplace le wildcard '*' permissif)
add_header Access-Control-Allow-Origin "https://${hostname}" always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS, PUT, DELETE" always;
add_header Access-Control-Allow-Headers "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization" always;
add_header Access-Control-Max-Age 1728000 always;
`;
  }

  if (hasEnvLeak || hasGitLeak) {
    conf += `
# 5. Blocage strict de l'accès aux fichiers sensibles et dossiers cachés
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}

location ~* /(?:\\.env|\\.git|composer\\.(?:json|lock)|package(?:-lock)?\\.json)$ {
    deny all;
    return 404;
}
`;
  }

  return {
    filename: `security-hardening-${hostname}.conf`,
    stack: 'Nginx',
    mimeType: 'text/plain',
    code: conf
  };
}

function generateApachePatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasServerLeak, hasEnvLeak, hasGitLeak, hasCorsFix, hasRedirectFix }) {
  let conf = `# ==============================================================================
# 🛡️ SECURSCAN AUTO-HARDENING PATCH POUR APACHE (.htaccess ou vhost)
# ==============================================================================

`;

  if (hasRedirectFix) {
    conf += `# Redirection HTTP vers HTTPS
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>\n\n`;
  }

  conf += `<IfModule mod_headers.c>
`;
  if (hasHsts) {
    conf += `    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n`;
  }
  if (hasXfo) {
    conf += `    Header always set X-Frame-Options "DENY"\n`;
  }
  if (hasXcto) {
    conf += `    Header always set X-Content-Type-Options "nosniff"\n`;
  }
  if (hasRef) {
    conf += `    Header always set Referrer-Policy "strict-origin-when-cross-origin"\n`;
  }
  if (hasPerm) {
    conf += `    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"\n`;
  }
  if (hasCsp) {
    conf += `    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none';"\n`;
  }
  if (hasCorsFix) {
    conf += `    Header always set Access-Control-Allow-Origin "null"\n`;
  }
  conf += `</IfModule>\n\n`;

  if (hasServerLeak) {
    conf += `# Masquer la signature serveur
ServerSignature Off
ServerTokens Prod\n\n`;
  }

  if (hasEnvLeak || hasGitLeak) {
    conf += `# Bloquer l'accès aux fichiers sensibles
<FilesMatch "^(\\.|composer\\.|package)">
    Require all denied
</FilesMatch>\n`;
  }

  return {
    filename: '.htaccess',
    stack: 'Apache',
    mimeType: 'text/plain',
    code: conf
  };
}

function generateExpressPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasServerLeak, hasCookieFix, hasCorsFix }) {
  let code = `// ==============================================================================
// 🛡️ SECURSCAN AUTO-HARDENING MIDDLEWARE POUR EXPRESS.JS (Node.js)
// ==============================================================================
import express from 'express';
// Recommandé : npm install helmet cors
import helmet from 'helmet';
import cors from 'cors';

export function applySecurityHardening(app) {
`;
  if (hasServerLeak) {
    code += `  // 1. Désactiver la fuite de l'en-tête X-Powered-By
  app.disable('x-powered-by');\n\n`;
  }

  if (hasCorsFix) {
    code += `  // 2. Politique CORS stricte (origine autorisée et méthodes sûres)
  app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
  }));\n\n`;
  }

  code += `  // 3. Configuration complète des en-têtes via Helmet
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
      }
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
  }));\n\n`;

  code += `  // 4. Permissions-Policy personnalisée
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });\n`;

  if (hasCookieFix) {
    code += `\n  // 5. Configuration recommandée pour les cookies de session (ex: express-session)
  // sessionOptions.cookie = {
  //   secure: true,      // Uniquement HTTPS
  //   httpOnly: true,    // Bloque l'accès document.cookie (Anti-XSS)
  //   sameSite: 'lax',   // Protection CSRF
  //   maxAge: 3600000    // 1 heure
  // };\n`;
  }

  code += `}\n`;

  return {
    filename: 'securityMiddleware.js',
    stack: 'Express.js',
    mimeType: 'text/javascript',
    code
  };
}

function generateNextjsPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasCorsFix }) {
  let code = `// ==============================================================================
// 🛡️ SECURSCAN AUTO-HARDENING POUR NEXT.JS (next.config.js ou next.config.mjs)
// ==============================================================================

/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false, // Supprime X-Powered-By
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
`;

  if (hasHsts) code += `          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },\n`;
  if (hasXfo) code += `          { key: 'X-Frame-Options', value: 'DENY' },\n`;
  if (hasXcto) code += `          { key: 'X-Content-Type-Options', value: 'nosniff' },\n`;
  if (hasRef) code += `          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },\n`;
  if (hasPerm) code += `          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },\n`;
  if (hasCsp) code += `          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';" },\n`;
  if (hasCorsFix) code += `          { key: 'Access-Control-Allow-Origin', value: 'https://example.com' },\n`;

  code += `        ],
      },
    ];
  },
};

export default nextConfig;
`;

  return {
    filename: 'next.config.mjs',
    stack: 'Next.js',
    mimeType: 'text/javascript',
    code
  };
}

function generateCaddyPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasCorsFix, hasRedirectFix, hostname }) {
  let code = `# ==============================================================================
# 🛡️ SECURSCAN AUTO-HARDENING POUR CADDY
# ==============================================================================

${hostname} {
`;
  if (hasRedirectFix) {
    code += `    # Redirection automatique vers HTTPS gérée nativement par Caddy
    # Caddy active par défaut le certificat Let's Encrypt et le port 443
`;
  }

  code += `    header {
`;
  if (hasHsts) code += `        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n`;
  if (hasXfo) code += `        X-Frame-Options "DENY"\n`;
  if (hasXcto) code += `        X-Content-Type-Options "nosniff"\n`;
  if (hasRef) code += `        Referrer-Policy "strict-origin-when-cross-origin"\n`;
  if (hasPerm) code += `        Permissions-Policy "camera=(), microphone=(), geolocation=()"\n`;
  if (hasCsp) code += `        Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"\n`;
  if (hasCorsFix) code += `        Access-Control-Allow-Origin "https://${hostname}"\n`;
  code += `        -Server
    }

    # Bloquer l'accès aux fichiers sensibles
    @hiddenFiles {
        path */.*
        path */.env*
        path */.git*
    }
    respond @hiddenFiles 404
}
`;

  return {
    filename: 'Caddyfile',
    stack: 'Caddy',
    mimeType: 'text/plain',
    code
  };
}

function generateVercelPatch({ hasCsp, hasHsts, hasXfo, hasXcto, hasRef, hasPerm, hasCorsFix }) {
  const headers = [];
  if (hasHsts) headers.push({ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' });
  if (hasXfo) headers.push({ key: 'X-Frame-Options', value: 'DENY' });
  if (hasXcto) headers.push({ key: 'X-Content-Type-Options', value: 'nosniff' });
  if (hasRef) headers.push({ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' });
  if (hasPerm) headers.push({ key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' });
  if (hasCsp) headers.push({ key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" });
  if (hasCorsFix) headers.push({ key: 'Access-Control-Allow-Origin', value: 'https://example.com' });

  const config = {
    cleanUrls: true,
    headers: [
      {
        source: '/(.*)',
        headers
      }
    ]
  };

  return {
    filename: 'vercel.json',
    stack: 'Vercel',
    mimeType: 'application/json',
    code: JSON.stringify(config, null, 2)
  };
}
