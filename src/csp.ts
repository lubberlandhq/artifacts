// Policies for the two kinds of origin. The content CSP follows the contract Claude publishes
// pages under: scripts from five pinned CDNs, stylesheets from Google Fonts, everything else
// inline, and no network access beyond the page's own origin.
export const SCRIPT_CDNS = [
  "https://cdnjs.cloudflare.com",
  "https://cdn.jsdelivr.net",
  "https://unpkg.com",
  "https://cdn.tailwindcss.com",
  "https://code.jquery.com",
];

export function contentCsp(appOrigin: string): string {
  const cdns = SCRIPT_CDNS.join(" ");
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: ${cdns}`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com ${cdns}`,
    "img-src 'self' data: blob: https:",
    "media-src 'self' data: blob: https:",
    "font-src 'self' data: https://fonts.gstatic.com",
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "frame-src 'self' blob: data:",
    "form-action 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    // Framable only by the viewer shell. A top-level visit (the "open full page" link) still works.
    `frame-ancestors ${appOrigin}`,
  ].join("; ");
}

export function shellCsp(nonce: string, contentOrigin: string | null): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    // Layout uses style="" attributes; attribute styles can't load or run anything.
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    contentOrigin ? `frame-src ${contentOrigin}` : "frame-src 'none'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
