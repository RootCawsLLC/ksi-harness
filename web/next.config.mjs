/** @type {import('next').NextConfig} */
const nextConfig = {
  // The ksi-harness tool is never imported into the web bundle. The run happens in a separate
  // Node process (scripts/run-ksi.mjs) that imports it natively, so there is nothing here to
  // externalize.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
