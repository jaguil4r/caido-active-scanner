import { Caido } from "@caido/sdk-frontend";

export const config = {
  name: "caido-active-scanner",
  id: "caido-active-scanner",
  version: "0.1.0",
  apiVersion: "0.48.0",
  description: "Replicates Burp Suite's Active and Passive Scanner features.",
  permissions: [
    "http.request",
    "http.response",
    "issues.write",
  ],
  backend: "packages/backend/index.ts",
  frontend: {
    sidebar: {
      icon: "bug_report",
      title: "Scanner",
      entrypoint: "packages/frontend/index.tsx",
    },
  },
  // TODO: Add details for signing keys for release
  // See: https://developer.caido.io/guides/developer/signing
}; 