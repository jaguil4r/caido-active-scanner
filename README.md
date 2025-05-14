# Burp-Like Scanner Plugin for Caido

This plugin aims to replicate the core functionality of Burp Suite's Active and Passive Scanners within the Caido environment.

## Features

*   **Passive Scanner:** Analyzes HTTP responses in the background for common vulnerabilities and informational findings (e.g., missing security headers, reflected parameters, version disclosures).
*   **Active Scanner:** Allows users to initiate scans against selected requests, sending modified payloads to detect vulnerabilities like XSS, SQLi, SSTI, etc.
*   **Sidebar UI:** Provides a dedicated panel to view reported issues and monitor the active scan queue.
*   **Context Menu Integration:** Right-click on requests in Caido to send them to the active scanner.

## Build

1.  **Install Dependencies:**
    ```bash
    npm install
    ```

2.  **Build the Plugin:**
    ```bash
    npm run build
    ```
    This command will generate the necessary JavaScript bundles for both the frontend and backend in the `dist/` directory and copy the `caido.config.ts` (as `caido.config.js`).

3.  **(Optional) Development Watch Mode:**
    To automatically rebuild on file changes during development:
    ```bash
    # Terminal 1: Watch frontend changes
    npm run dev:frontend

    # Terminal 2: Watch backend changes
    npm run dev:backend
    ```

## Installation in Caido

1.  Open Caido.
2.  Navigate to the **Settings** page (gear icon).
3.  Go to the **Plugins** section.
4.  Click **Import Plugin**.
5.  Select the `caido.config.ts` file (or the generated `caido.config.js` after build) from the root of this project directory.
6.  Enable the plugin if it's not enabled automatically.

## Usage

*   **Passive Scanning:** Runs automatically on proxied traffic. Findings will appear in the "Scanner" sidebar panel under the "Issues" tab.
*   **Active Scanning:**
    1.  Find a request you want to scan in Caido's HTTP History or other tools.
    2.  Right-click the request.
    3.  Select "Actively scan with Burp-Like Scanner".
    4.  The scan will be added to the queue, visible in the "Scanner" sidebar panel under the "Scan Queue" tab.
    5.  Findings from the active scan will appear in the "Issues" tab.

## Development Notes

*   **Signing:** For local development, the plugin is unsigned. For releasing the plugin, you will need to generate signing keys and configure them in `caido.config.ts`. Refer to the [Caido Developer Documentation](https://developer.caido.io/guides/developer/signing) for details.
*   **Testing:** Unit tests for backend logic can be run using:
    ```bash
    npm test
    ```

## TODO / Stretch Goals

*   Implement detailed payload libraries in `lib/payloads.ts`.
*   Refine concurrency and throttling for active scans.
*   Add heuristic scan-profile selection based on content-type.
*   Utilize Caido's rate-limit helper once available.
*   Implement Export/Import scan results to JSON.
*   Improve error handling and logging.
*   Add more passive check rules.
*   Allow configuration of scan settings (e.g., specific checks, payload sets). 