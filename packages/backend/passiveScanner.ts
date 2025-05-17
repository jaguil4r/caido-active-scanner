import {
    Caido,
    HttpResponse,
    HttpRequest,
    Severity,
    Confidence,
    // QueryParameter, // Not directly used in passive checks here, but good to keep if extending
    // Header, // Not directly used in passive checks here
} from "@caido/sdk-backend";
import { PLUGIN_ID } from "./constants"; // Import PLUGIN_ID

// Define PLUGIN_ID here or import from a shared constants file if it exists
// const PLUGIN_ID = "burp-like-scanner"; // MOVED to constants.ts

// --- Passive Scanner Helpers ---

/**
 * Checks for common missing security headers or insecure values.
 * Returns an array of descriptions for findings.
 * @private - Exported for testing only, ensure tests point to this new location
 */
export const checkMissingSecurityHeaders = (response: HttpResponse): string[] => {
  const findings: string[] = [];
  const headers = response.getHeaders();
  const headerMap = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]));

  const requiredHeaders = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
  ];

  requiredHeaders.forEach(headerName => {
    if (!headerMap.has(headerName)) {
      findings.push(`Missing security header: ${headerName}`);
    }
  });

  const xContentTypeOptions = headerMap.get('x-content-type-options');
  if (!xContentTypeOptions) {
      findings.push(`Missing security header: x-content-type-options`);
  } else if (xContentTypeOptions.toLowerCase() !== 'nosniff') {
      findings.push(`Insecure value for x-content-type-options: "${xContentTypeOptions}". Expected "nosniff".`);
  }

  return findings;
};

/**
 * Checks for reflected query or body parameters in the response body.
 * Returns an array of reflected parameter names.
 * @private - Exported for testing only, ensure tests point to this new location
 */
export const checkReflectedParameters = (request: HttpRequest, response: HttpResponse): string[] => {
    const reflectedParams: string[] = [];
    const responseBody = response.getBodyAsString();
    if (!responseBody) return reflectedParams;

    const paramsToCheck: { name: string; value: string }[] = [];
    paramsToCheck.push(...request.getQueryParameters());

    const contentType = request.getHeader('content-type')?.toLowerCase() || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
        // TODO: Add body parameter parsing if Caido SDK provides it easily
        // For now, skipping body params as in the original file.
        // if (request.getBodyParameters) paramsToCheck.push(...request.getBodyParameters()); 
    }

    paramsToCheck.forEach(param => {
        if (param.value && param.value.length > 2 && param.value.length < 100 && responseBody.includes(param.value)) {
            reflectedParams.push(param.name);
        }
    });
    return [...new Set(reflectedParams)];
};

/**
 * Checks for common headers disclosing server/framework version information.
 * Returns an array of descriptions for findings.
 * @private - Exported for testing only, ensure tests point to this new location
 */
export const checkServerVersionDisclosure = (response: HttpResponse): string[] => {
    const findings: string[] = [];
    const headersToCheck = ['server', 'x-powered-by', 'x-aspnet-version'];
    const headers = response.getHeaders();
    const versionRegex = /[\d\.]+/;

    headersToCheck.forEach(headerName => {
        const lowerCaseHeader = headerName.toLowerCase();
        const headerEntry = Object.entries(headers).find(([k]) => k.toLowerCase() === lowerCaseHeader);
        
        if (headerEntry) {
            const headerValue = String(headerEntry[1]);
            if (headerValue && typeof headerValue === 'string' && versionRegex.test(headerValue)) {
                if (headerValue.length > headerName.length + 2) { 
                    findings.push(`Potential version disclosure via header: ${headerName}: ${headerValue}`);
                }
            }
        }
    });
    return findings;
};

// --- Main Passive Scanner Logic ---
export const runPassiveChecks = (caido: Caido, response: HttpResponse) => {
  // Original runPassiveChecks logic from backend/index.ts
  caido.log("Passive check running (from passiveScanner.ts)..." );
  const request = response.getRequest();
  const requestId = request.getId();

  const headerFindings = checkMissingSecurityHeaders(response);
  headerFindings.forEach(finding => {
      caido.issues.create({
          pluginId: PLUGIN_ID,
          title: "Insecure Header Configuration",
          severity: Severity.LOW,
          confidence: Confidence.CERTAIN,
          description: finding,
          affectedRequestId: requestId,
      });
  });

  const reflectedParams = checkReflectedParameters(request, response);
  reflectedParams.forEach(paramName => {
      caido.issues.create({
          pluginId: PLUGIN_ID,
          title: `Reflected Input Parameter: ${paramName}`,
          severity: Severity.INFO,
          confidence: Confidence.TENTATIVE,
          description: `The value of parameter "${paramName}" was found reflected in the response body. This might indicate potential cross-site scripting (XSS) vulnerabilities if user input is not properly sanitized. Manual verification is recommended.`,
          affectedRequestId: requestId,
      });
  });

  const versionFindings = checkServerVersionDisclosure(response);
  versionFindings.forEach(finding => {
      caido.issues.create({
          pluginId: PLUGIN_ID,
          title: "Server Version Disclosure",
          severity: Severity.INFO,
          confidence: Confidence.FIRM, 
          description: finding + "\n\nLeaking specific software versions can help attackers identify known vulnerabilities.",
          affectedRequestId: requestId,
      });
  });
  caido.log("Passive check finished (from passiveScanner.ts).");
}; 