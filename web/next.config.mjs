// Security headers on every response (OWASP HTTP Headers Cheat Sheet). The CSP
// uses 'unsafe-inline' for scripts because this GUI has no per-request nonce
// middleware; when it is next deployed, move to a nonce-based CSP (as in the
// trust-center app) and drop 'unsafe-inline'. Verify live with `curl -sI`.
const csp = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "img-src 'self' data: blob:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "upgrade-insecure-requests",
].join("; ");
const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), interest-cohort=()" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  // The ksi-harness tool is never imported into the web bundle. The run happens in a separate
  // Node process (scripts/run-ksi.mjs) that imports it natively, so there is nothing here to
  // externalize.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
