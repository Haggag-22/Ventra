/** @type {import('next').NextConfig} */
const API = process.env.VENTRA_API || "http://127.0.0.1:8000";
const staticExport = process.env.VENTRA_STATIC_EXPORT === "1";

const nextConfig = {
  reactStrictMode: true,
  images: { unoptimized: true },
  ...(staticExport
    ? {
        output: "export",
        trailingSlash: true,
      }
    : {
        // Dev / next start: proxy API calls to the backend (same-origin in packaged mode).
        async rewrites() {
          return [{ source: "/api/:path*", destination: `${API}/api/:path*` }];
        },
      }),
};

module.exports = nextConfig;
