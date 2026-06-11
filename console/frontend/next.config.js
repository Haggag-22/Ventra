/** @type {import('next').NextConfig} */
const API = process.env.HARBOR_API || "http://127.0.0.1:8000";

const nextConfig = {
  reactStrictMode: true,
  // Proxy API calls to the backend so the frontend makes no cross-origin/external calls.
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API}/api/:path*` }];
  },
  // No telemetry, no external image domains — the console is offline-first.
  images: { unoptimized: true },
};

module.exports = nextConfig;
