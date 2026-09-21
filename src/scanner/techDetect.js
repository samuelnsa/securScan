/**
 * Module de détection de technologies (fingerprinting passif)
 * Identifie les frameworks, CMS, langages et serveurs utilisés via les en-têtes et réponses HTTP.
 */

const TECH_SIGNATURES = [
  // Serveurs Web
  { pattern: /nginx/i, header: 'server', name: 'Nginx', category: 'Serveur Web', icon: '🌐' },
  { pattern: /apache/i, header: 'server', name: 'Apache', category: 'Serveur Web', icon: '🪶' },
  { pattern: /cloudflare/i, header: 'server', name: 'Cloudflare', category: 'CDN / Proxy', icon: '☁️' },
  { pattern: /microsoft-iis/i, header: 'server', name: 'Microsoft IIS', category: 'Serveur Web', icon: '🟦' },
  { pattern: /litespeed/i, header: 'server', name: 'LiteSpeed', category: 'Serveur Web', icon: '⚡' },
  { pattern: /caddy/i, header: 'server', name: 'Caddy', category: 'Serveur Web', icon: '🔒' },
  { pattern: /openresty/i, header: 'server', name: 'OpenResty', category: 'Serveur Web', icon: '🔧' },

  // Langages / Runtimes
  { pattern: /express/i, header: 'x-powered-by', name: 'Express.js (Node.js)', category: 'Framework', icon: '🟢' },
  { pattern: /php/i, header: 'x-powered-by', name: 'PHP', category: 'Langage', icon: '🐘' },
  { pattern: /asp\.net/i, header: 'x-powered-by', name: 'ASP.NET', category: 'Framework', icon: '🟣' },
  { pattern: /next\.?js/i, header: 'x-powered-by', name: 'Next.js', category: 'Framework', icon: '▲' },
  { pattern: /nuxt/i, header: 'x-powered-by', name: 'Nuxt.js', category: 'Framework', icon: '💚' },
  { pattern: /django/i, header: 'x-powered-by', name: 'Django', category: 'Framework', icon: '🐍' },

  // CDN / Proxy
  { pattern: /cloudflare/i, header: 'cf-ray', name: 'Cloudflare', category: 'CDN / Proxy', icon: '☁️', presenceOnly: true },
  { pattern: /.+/i, header: 'x-vercel-id', name: 'Vercel', category: 'Hosting / PaaS', icon: '▲', presenceOnly: true },
  { pattern: /.+/i, header: 'x-amz-cf-id', name: 'Amazon CloudFront', category: 'CDN / Proxy', icon: '🟠', presenceOnly: true },
  { pattern: /.+/i, header: 'x-azure-ref', name: 'Azure CDN', category: 'CDN / Proxy', icon: '🔵', presenceOnly: true },
  { pattern: /.+/i, header: 'x-fastly-request-id', name: 'Fastly', category: 'CDN / Proxy', icon: '🔴', presenceOnly: true },
  { pattern: /.+/i, header: 'fly-request-id', name: 'Fly.io', category: 'Hosting / PaaS', icon: '✈️', presenceOnly: true },
  { pattern: /.+/i, header: 'x-render-origin-server', name: 'Render', category: 'Hosting / PaaS', icon: '🟩', presenceOnly: true },
  { pattern: /.+/i, header: 'x-heroku-queue-depth', name: 'Heroku', category: 'Hosting / PaaS', icon: '💜', presenceOnly: true },

  // Security / WAF
  { pattern: /sucuri/i, header: 'server', name: 'Sucuri WAF', category: 'WAF', icon: '🛡️' },
  { pattern: /.+/i, header: 'x-sucuri-id', name: 'Sucuri WAF', category: 'WAF', icon: '🛡️', presenceOnly: true },
  { pattern: /akamai/i, header: 'server', name: 'Akamai', category: 'CDN / WAF', icon: '🔷' },

  // CMS hints from cookies
  { pattern: /wordpress/i, header: 'x-powered-by', name: 'WordPress', category: 'CMS', icon: '📝' },
  { pattern: /wp-/i, header: 'link', name: 'WordPress', category: 'CMS', icon: '📝' },
];

const COOKIE_TECH_PATTERNS = [
  { pattern: /^__cfduid$/i, name: 'Cloudflare', category: 'CDN / Proxy', icon: '☁️' },
  { pattern: /^PHPSESSID$/i, name: 'PHP', category: 'Langage', icon: '🐘' },
  { pattern: /^JSESSIONID$/i, name: 'Java (Servlet/Tomcat)', category: 'Langage', icon: '☕' },
  { pattern: /^ASP\.NET_SessionId$/i, name: 'ASP.NET', category: 'Framework', icon: '🟣' },
  { pattern: /^connect\.sid$/i, name: 'Express.js (Node.js)', category: 'Framework', icon: '🟢' },
  { pattern: /^_rails_/i, name: 'Ruby on Rails', category: 'Framework', icon: '💎' },
  { pattern: /^laravel_session$/i, name: 'Laravel (PHP)', category: 'Framework', icon: '🔴' },
  { pattern: /^wp-settings-/i, name: 'WordPress', category: 'CMS', icon: '📝' },
  { pattern: /^wordpress_/i, name: 'WordPress', category: 'CMS', icon: '📝' },
  { pattern: /^_ga$/i, name: 'Google Analytics', category: 'Analytics', icon: '📊' },
  { pattern: /^_fbp$/i, name: 'Facebook Pixel', category: 'Analytics', icon: '📘' },
];

export function detectTechnologies(headers, setCookieHeaders = '') {
  const detected = new Map(); // key: name, value: { name, category, icon, confidence, evidence[] }

  const lowerHeaders = {};
  for (const [key, val] of Object.entries(headers)) {
    lowerHeaders[key.toLowerCase()] = val;
  }

  // 1. Scan des en-têtes HTTP
  for (const sig of TECH_SIGNATURES) {
    const headerVal = lowerHeaders[sig.header];
    if (!headerVal) continue;

    if (sig.presenceOnly || sig.pattern.test(headerVal)) {
      if (!detected.has(sig.name)) {
        detected.set(sig.name, {
          name: sig.name,
          category: sig.category,
          icon: sig.icon,
          confidence: sig.presenceOnly ? 'HIGH' : 'CONFIRMED',
          evidence: []
        });
      }
      const entry = detected.get(sig.name);
      const evidenceText = sig.presenceOnly
        ? `En-tête ${sig.header} présent`
        : `En-tête ${sig.header}: ${typeof headerVal === 'string' ? headerVal.substring(0, 80) : headerVal}`;
      
      if (!entry.evidence.includes(evidenceText)) {
        entry.evidence.push(evidenceText);
      }
    }
  }

  // 2. Scan des cookies
  if (setCookieHeaders) {
    const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const cookieStr of cookies) {
      const cookieName = cookieStr.split('=')[0]?.trim();
      if (!cookieName) continue;

      for (const cp of COOKIE_TECH_PATTERNS) {
        if (cp.pattern.test(cookieName)) {
          if (!detected.has(cp.name)) {
            detected.set(cp.name, {
              name: cp.name,
              category: cp.category,
              icon: cp.icon,
              confidence: 'MEDIUM',
              evidence: []
            });
          }
          const entry = detected.get(cp.name);
          entry.evidence.push(`Cookie: ${cookieName}`);
        }
      }
    }
  }

  // 3. Détection via cache-control et autres heuristiques
  if (lowerHeaders['x-cache']) {
    const xCache = lowerHeaders['x-cache'];
    if (/varnish/i.test(xCache)) {
      detected.set('Varnish', {
        name: 'Varnish',
        category: 'Cache / Proxy',
        icon: '🔶',
        confidence: 'HIGH',
        evidence: [`X-Cache: ${xCache}`]
      });
    }
  }

  return Array.from(detected.values());
}
