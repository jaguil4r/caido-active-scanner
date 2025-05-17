Project: Burp-Like Scanner (Caido Plugin)
Goal: Create a Caido plugin that replicates core functionalities of Burp Suite's Active and Passive Scanners, allowing users to identify common web vulnerabilities.

Phase 1: MVP - Testable Core Functionality
(Objective: Get the plugin to a state where basic passive and active scans can run and produce results within Caido, focusing on a few key vulnerability types and injection points.)

Consolidate Constants:
 Create backend/constants.ts for PLUGIN_ID, FRONTEND_UPDATE_COMMAND, REQUEST_THROTTLE_MS, MAX_CONCURRENT_SCANS.
 Update backend/index.ts, backend/passiveScanner.ts, and backend/activeScanner.ts to import constants from this new file.
Verify SDK Method Assumptions for Active Scanner:
 Crucial for testing: Confirm HttpRequest.getBodyParameters() and HttpRequest.setBodyParameters() (or equivalents for manipulating form-data body parameters as an array of objects) exist and function as expected in the Caido SDK. (Confirmed: High-level helpers do not exist for form data; manual parsing/serialization with URLSearchParams and reqSpec.setBody(new Body(...)) is required.)
 If not, implement manual parsing/serialization for application/x-www-form-urlencoded bodies in performSingleScan within backend/activeScanner.ts. (Implemented)
Basic Build and Test Setup:
 Ensure npm run build completes successfully, creating dist/frontend and dist/backend outputs.
 Manually install the built plugin into a Caido instance.
 Perform a basic E2E test:
Target a simple test application (e.g., a locally running instance of DVWA or a deliberately vulnerable an application you have set up for testing).
Trigger passive checks by browsing.
Trigger an active scan from the context menu on a request with query parameters.
Verify issues are logged in the "Issues" tab.
Verify scan appears in the "Scan Queue" tab and updates its status.
Address Critical Linter/Runtime Errors:
 Specifically investigate and resolve the persistent "Cannot find module '@caido/sdk-backend' (and frontend)" errors. This is likely an environment/TS configuration issue that needs to be sorted out for stable development and testing. It might involve checking tsconfig.json paths, ensuring correct SDK installation, or IDE-specific settings.
Phase 2: Enhancements & User Features
(Objective: Improve detection capabilities, expand scan coverage, and add user-facing features like the "WAF Bypass" test mode.)

"WAF Bypass Test" / HTML Reflection Check (Passive & Active):
Passive Component:
 In backend/passiveScanner.ts, add a new check to runPassiveChecks.
 This check will specifically look for reflections of simple HTML tags (e.g., <b>, <i>, <u>) from request parameters (query & body) into HTML responses.
 Create a new, distinct issue type for this (e.g., "HTML Tag Reflected - Potential WAF Bypass Test Point" or "Non-Malicious HTML Reflection"), with Severity.INFO.
Active Component (Simple Probing):
 In backend/activeScanner.ts (performSingleScan):
Add a new payload category, e.g., HTML_REFLECTION_PROBES in lib/payloads.ts with payloads like <b>caido_test</b>, <i>caido_test</i>.
When this category is scanned, analyzeResponse should specifically look for the exact reflection of these harmless tags.
If reflected in an HTML context, create an INFO level issue like "Harmless HTML Probe Reflected".
Frontend Setting (Later):
 (Stretch Goal for this phase) Add a toggle in the plugin's sidebar UI: "Enable WAF Bypass/HTML Reflection Probing". This setting would control whether these specific passive and active checks run.
Expand Active Scan Injection Points:
 HTTP Headers: Inject payloads into common HTTP request headers in performSingleScan.
 Cookie Values: Inject payloads into cookie values.
 URL Path Segments (More complex, consider for later within this phase).
Improve analyzeResponse Reliability:
 Contextual XSS Analysis: For XSS, attempt to determine if reflection occurs within HTML tags, attributes, script blocks, etc., to refine confidence/severity.
 SSTI Confirmation: For SSTI, if a simple math evaluation (e.g., 7*7=49) is found, attempt a follow-up request with a payload designed to reveal the template engine itself (e.g., by causing slightly different errors or reflections based on common template syntaxes).
Unit Testing:
 Add/improve unit tests for backend/passiveScanner.ts (if current tests need updating due to refactor).
 Add unit tests for backend/activeScanner.ts, focusing on analyzeResponse for various payload/response scenarios and key parts of performSingleScan's injection logic (can be mocked).
Frontend Polish:
 Display more scan progress details in the "Scan Queue" (e.g., current category, # requests sent).
 Allow users to cancel a running scan from the frontend.
Phase 3: Advanced Features & Robustness
(Objective: Add more advanced scanning techniques, improve configuration, and make the plugin more robust and user-friendly.)

**Advanced analyzeResponse 