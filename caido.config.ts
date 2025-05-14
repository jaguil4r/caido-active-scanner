import { Caido } from "@caido/sdk-frontend";

export const config = {
  name: "Burp-Like Scanner",
  id: "burp-like-scanner",
  version: "0.1.0",
  apiVersion: "0.48.0",
  description: "Replicates Burp Suite's Active and Passive Scanner features.",
  permissions: [
    "http.request",
    "http.response",
    "issues.write",
  ],
  backend: "dist/backend/index.js", // Built by esbuild
  frontend: {
    sidebar: {
      icon: "bug_report",
      title: "Scanner",
      entrypoint: "frontend/index.tsx", // Adjusted for Vite dev server
    },
  },
  // TODO: Add details for signing keys for release
  // See: https://developer.caido.io/guides/developer/signing
}; 