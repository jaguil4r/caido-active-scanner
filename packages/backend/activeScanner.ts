import {
    Caido,
    HttpResponse,
    HttpRequest,
    Severity,
    Confidence,
    QueryParameter,
    Body,
    RequestSpec
} from "@caido/sdk-backend";
import { ALL_PAYLOADS } from "../lib/payloads";
import { PLUGIN_ID, REQUEST_THROTTLE_MS } from "./constants"; // Import constants

// Define constants here or import from a shared constants file
// const PLUGIN_ID = "burp-like-scanner"; // MOVED to constants.ts
// const REQUEST_THROTTLE_MS = 500; // MOVED to constants.ts

// --- Active Scanner Analysis Logic ---
interface ActiveScanFinding {
    type: string; 
    evidence: string;
    severity: Severity;
    confidence: Confidence;
    parameter?: string; 
}

interface ActiveScanResult {
    isVulnerable: boolean;
    finding?: ActiveScanFinding;
}

// This function can remain unexported if only used within this file
const analyzeResponse = (caido: Caido, payload: string, payloadCategory: keyof typeof ALL_PAYLOADS, response: HttpResponse, request: HttpRequest): ActiveScanResult => {
    // ... (Exact same content of analyzeResponse from backend/index.ts) ...
    // For brevity in this prompt, I'm not pasting the full 60+ lines of analyzeResponse here
    // but it should be the complete function as it currently exists.
    caido.log(`Analyzing response for ${payloadCategory} payload: ${payload.substring(0, 50)}... on ${request.getUrl()} (from activeScanner.ts)`);
    const responseBody = response.getBodyAsString();
    const contentType = response.getHeader('Content-Type')?.toLowerCase() || '';

    // XSS Detection
    if (payloadCategory === 'xss' && responseBody.includes(payload)) {
        let xssConfidence = Confidence.TENTATIVE;
        let xssSeverity = Severity.MEDIUM;
        let evidenceDetails = `Payload reflected in response body. Content-Type: ${contentType || 'Not set'}`;
        if (contentType.includes('text/html') || contentType.includes('application/xhtml+xml') || contentType.includes('application/xml')) {
            xssConfidence = Confidence.FIRM;
            xssSeverity = Severity.HIGH;
            evidenceDetails = `Payload reflected in HTML/XML response body (Content-Type: ${contentType}): ${payload.substring(0, 100)}...`;
        } else if (contentType.includes('application/json')) {
            xssConfidence = Confidence.TENTATIVE;
            xssSeverity = Severity.LOW;
            evidenceDetails = `Payload reflected in JSON response body (Content-Type: ${contentType}). This may not be directly exploitable as XSS unless the JSON is embedded in an HTML page unsafely: ${payload.substring(0, 100)}...`;
        } else {
            xssSeverity = Severity.LOW;
            evidenceDetails = `Payload reflected in response body (Content-Type: ${contentType}): ${payload.substring(0, 100)}...`;
        }
        return {
            isVulnerable: true,
            finding: {
                type: "Cross-Site Scripting (Reflected)",
                evidence: evidenceDetails,
                severity: xssSeverity,
                confidence: xssConfidence,
            }
        };
    }

    // SQLi Detection
    if (payloadCategory === 'sqli') {
        const sqlErrorPatterns = [
            /SQL syntax.*?MySQL/i, /You have an error in your SQL syntax/i,
            /syntax error.*?PostgreSQL/i, 
            /ORA-[0-9][0-9][0-9][0-9][0-9]/i, 
            /Unclosed quotation mark after the character string/i, /Statement\(s\) could not be prepared/i, /Incorrect syntax near/i,
            /sqlite3.OperationalError/i, /near ".*?": syntax error/i,
        ];
        for (const pattern of sqlErrorPatterns) {
            if (pattern.test(responseBody)) {
                return {
                    isVulnerable: true,
                    finding: {
                        type: "SQL Injection Error",
                        evidence: `Potential SQL error detected matching pattern: ${pattern.toString()}`,
                        severity: Severity.HIGH,
                        confidence: Confidence.FIRM,
                    }
                };
            }
        }
    }
  
    // SSTI Detection
    if (payloadCategory === 'ssti' && responseBody.includes("49")) {
        const wasMathPayload = payload.includes("7*7") || payload.includes("{{7*7}}") || payload.includes("${7*7}") || payload.includes("<%= 7*7 %>") || payload.includes("#{ 7*7 }") || payload.includes("@(7*7)");
        if (wasMathPayload) { 
            return {
                isVulnerable: true,
                finding: {
                    type: "Server-Side Template Injection (Potential)",
                    evidence: `Numerical expression '${payload}' potentially evaluated to '49' in response. Original payload: ${payload.substring(0,100)}...`,
                    severity: Severity.HIGH,
                    confidence: Confidence.TENTATIVE,
                }
            };
        }
    }
    return { isVulnerable: false };
};

// --- Core Active Scanning Orchestration ---
export const performSingleScan = async (caido: Caido, baseRequest: HttpRequest, scanId: string) => {
    caido.log(`PerformSingleScan started for scanId: ${scanId}, request: ${baseRequest.getUrl()} (from activeScanner.ts)`);
    let issuesFound = 0;

    for (const category of Object.keys(ALL_PAYLOADS) as (keyof typeof ALL_PAYLOADS)[]) {
        const payloads = ALL_PAYLOADS[category];
        caido.log(`[${scanId}] Testing category: ${category} with ${payloads.length} payloads.`);

        // --- Query Parameter Injection ---
        for (const payload of payloads) {
            const originalQueryParameters = baseRequest.getQueryParameters();
            for (let i = 0; i < originalQueryParameters.length; i++) {
                const paramToModify = originalQueryParameters[i];
                const clonedRequestSpec = baseRequest.toSpec();
                const newQueryParams: QueryParameter[] = originalQueryParameters.map((p: QueryParameter, index: number) => 
                    index === i ? { name: p.name, value: payload } : p
                );
                clonedRequestSpec.setQueryParameters(newQueryParams);

                try {
                    const modifiedHttpRequest = clonedRequestSpec.toRequest();
                    caido.log.debug(`[${scanId}] Sending request (param replace): ${modifiedHttpRequest.getUrl()} with payload for param ${paramToModify.name}`);
                    const modifiedResponse = await caido.http.request(modifiedHttpRequest);
                    const analysisResult = analyzeResponse(caido, payload, category, modifiedResponse, modifiedHttpRequest);
                    if (analysisResult.isVulnerable && analysisResult.finding) {
                        issuesFound++;
                        const finding = analysisResult.finding;
                        caido.issues.create({
                            pluginId: PLUGIN_ID,
                            title: `${finding.type} in parameter: ${paramToModify.name}`,
                            severity: finding.severity, confidence: finding.confidence,
                            description: `Vulnerability: ${finding.type}\nAffected Parameter: ${paramToModify.name}\nPayload: ${payload}\nEvidence: ${finding.evidence}\n\nOriginal Request: ${baseRequest.getMethod()} ${baseRequest.getUrl()}`,
                            affectedRequestId: modifiedResponse.getRequest().getId(),
                        });
                        caido.log.info(`[${scanId}] Issue found: ${finding.type} in ${paramToModify.name} with payload ${payload}`);
                    }
                } catch (reqError) { caido.log.warn(`[${scanId}] Error sending request (param replace ${paramToModify.name}): ${reqError}`); }
                await new Promise(resolve => setTimeout(resolve, REQUEST_THROTTLE_MS));
            }

            const clonedRequestSpecNewQuery = baseRequest.toSpec();
            const newQueryParamName = `caido_test_${category}`;
            const currentQueryParams = clonedRequestSpecNewQuery.getQueryParameters();
            clonedRequestSpecNewQuery.setQueryParameters([...currentQueryParams, { name: newQueryParamName, value: payload }]);
            try {
                const modifiedHttpRequest = clonedRequestSpecNewQuery.toRequest();
                caido.log.debug(`[${scanId}] Sending request (new query param): ${modifiedHttpRequest.getUrl()} with new param ${newQueryParamName}`);
                const modifiedResponse = await caido.http.request(modifiedHttpRequest);
                const analysisResult = analyzeResponse(caido, payload, category, modifiedResponse, modifiedHttpRequest);
                if (analysisResult.isVulnerable && analysisResult.finding) {
                    issuesFound++;
                    const finding = analysisResult.finding; 
                    caido.issues.create({
                        pluginId: PLUGIN_ID, 
                        title: `${finding.type} via new parameter: ${newQueryParamName}`, 
                        severity: finding.severity, confidence: finding.confidence,
                        description: `Vulnerability: ${finding.type}\nInjected Parameter: ${newQueryParamName}\nPayload: ${payload}\nEvidence: ${finding.evidence}\n\nOriginal Request: ${baseRequest.getMethod()} ${baseRequest.getUrl()}`,
                        affectedRequestId: modifiedResponse.getRequest().getId(),
                    });
                    caido.log.info(`[${scanId}] Issue found: ${finding.type} via new param ${newQueryParamName} with payload ${payload}`);
                }
            } catch (reqError) { caido.log.warn(`[${scanId}] Error sending request (new query param ${newQueryParamName}): ${reqError}`); }
            await new Promise(resolve => setTimeout(resolve, REQUEST_THROTTLE_MS));
        }

        // --- Form Body Parameter Injection (application/x-www-form-urlencoded) ---
        const baseContentType = baseRequest.getHeader('Content-Type')?.toLowerCase() || '';
        if (baseContentType.includes('application/x-www-form-urlencoded')) {
            caido.log(`[${scanId}] Testing Form Body parameters for category: ${category}`);
            const originalBodyStr = baseRequest.getBody()?.toText() ?? "";
            const originalBodyUrlSearchParams = new URLSearchParams(originalBodyStr);
            
            // Create a list of original param names to iterate over, as URLSearchParams iteration can be tricky
            const originalParamNames: string[] = [];
            originalBodyUrlSearchParams.forEach((_, name) => {
                if (!originalParamNames.includes(name)) { // Ensure unique names if multiple have same name
                    originalParamNames.push(name);
                }
            });

            for (const payload of payloads) {
                // 3a. Test by replacing existing form body parameter values
                for (const paramNameToModify of originalParamNames) {
                    const clonedRequestSpec = baseRequest.toSpec();
                    const currentBodyParams = new URLSearchParams(originalBodyStr);
                    currentBodyParams.set(paramNameToModify, payload);
                    clonedRequestSpec.setBody(new Body(currentBodyParams.toString()));

                    try {
                        const modifiedHttpRequest = clonedRequestSpec.toRequest();
                        caido.log.debug(`[${scanId}] Sending request (form body replace): ${modifiedHttpRequest.getUrl()} with payload for param ${paramNameToModify}`);
                        const modifiedResponse = await caido.http.request(modifiedHttpRequest);
                        const analysisResult = analyzeResponse(caido, payload, category, modifiedResponse, modifiedHttpRequest);
                        if (analysisResult.isVulnerable && analysisResult.finding) {
                            issuesFound++;
                            const finding = analysisResult.finding;
                            caido.issues.create({
                                pluginId: PLUGIN_ID,
                                title: `${finding.type} in FORM parameter: ${paramNameToModify}`,
                                severity: finding.severity, confidence: finding.confidence,
                                description: `Vulnerability: ${finding.type}\nAffected FORM Parameter: ${paramNameToModify}\nPayload: ${payload}\nEvidence: ${finding.evidence}\n\nOriginal Request: ${baseRequest.getMethod()} ${baseRequest.getUrl()}`,
                                affectedRequestId: modifiedResponse.getRequest().getId(),
                            });
                            caido.log.info(`[${scanId}] Issue found: ${finding.type} in FORM param ${paramNameToModify} with payload ${payload}`);
                        }
                    } catch (reqError) { caido.log.warn(`[${scanId}] Error sending request (form body replace ${paramNameToModify}): ${reqError}`); }
                    await new Promise(resolve => setTimeout(resolve, REQUEST_THROTTLE_MS));
                }

                // 3b. Test by adding payload as a new form body parameter
                const clonedRequestSpecNewForm = baseRequest.toSpec();
                const newFormParamName = `caido_test_form_${category}`;
                const currentBodyParamsForNew = new URLSearchParams(originalBodyStr);
                currentBodyParamsForNew.append(newFormParamName, payload);
                clonedRequestSpecNewForm.setBody(new Body(currentBodyParamsForNew.toString()));

                try {
                    const modifiedHttpRequest = clonedRequestSpecNewForm.toRequest();
                    caido.log.debug(`[${scanId}] Sending request (new form body param): ${modifiedHttpRequest.getUrl()} with new param ${newFormParamName}`);
                    const modifiedResponse = await caido.http.request(modifiedHttpRequest);
                    const analysisResult = analyzeResponse(caido, payload, category, modifiedResponse, modifiedHttpRequest);
                    if (analysisResult.isVulnerable && analysisResult.finding) {
                        issuesFound++;
                        const finding = analysisResult.finding;
                        caido.issues.create({
                            pluginId: PLUGIN_ID,
                            title: `${finding.type} via new FORM parameter: ${newFormParamName}`,
                            severity: finding.severity, confidence: finding.confidence,
                            description: `Vulnerability: ${finding.type}\nInjected FORM Parameter: ${newFormParamName}\nPayload: ${payload}\nEvidence: ${finding.evidence}\n\nOriginal Request: ${baseRequest.getMethod()} ${baseRequest.getUrl()}`,
                            affectedRequestId: modifiedResponse.getRequest().getId(),
                        });
                        caido.log.info(`[${scanId}] Issue found: ${finding.type} via new FORM param ${newFormParamName} with payload ${payload}`);
                    }
                } catch (reqError) { caido.log.warn(`[${scanId}] Error sending request (new form body param ${newFormParamName}): ${reqError}`); }
                await new Promise(resolve => setTimeout(resolve, REQUEST_THROTTLE_MS));
            }
        } 

        // --- JSON Body Parameter Injection (application/json) ---
        if (baseContentType.includes('application/json')) {
            caido.log(`[${scanId}] Testing JSON Body for category: ${category}`);
            const originalBodyStr = baseRequest.getBody()?.toText() ?? "";
            if (originalBodyStr) {
                try {
                    const originalJsonBody = JSON.parse(originalBodyStr);
                    for (const payload of payloads) {
                        for (const key in originalJsonBody) {
                            if (Object.prototype.hasOwnProperty.call(originalJsonBody, key) && typeof originalJsonBody[key] === 'string') {
                                const clonedRequestSpec = baseRequest.toSpec();
                                const modifiedJsonBody = { ...originalJsonBody };
                                modifiedJsonBody[key] = payload;
                                clonedRequestSpec.setBody(new Body(JSON.stringify(modifiedJsonBody)));

                                try {
                                    const modifiedHttpRequest = clonedRequestSpec.toRequest();
                                    caido.log.debug(`[${scanId}] Sending request (JSON body replace key ${key}): ${modifiedHttpRequest.getUrl()}`);
                                    const modifiedResponse = await caido.http.request(modifiedHttpRequest);
                                    const analysisResult = analyzeResponse(caido, payload, category, modifiedResponse, modifiedHttpRequest);
                                    if (analysisResult.isVulnerable && analysisResult.finding) {
                                        issuesFound++;
                                        const finding = analysisResult.finding;
                                        caido.issues.create({
                                            pluginId: PLUGIN_ID,
                                            title: `${finding.type} in JSON key: ${key}`,
                                            severity: finding.severity, confidence: finding.confidence,
                                            description: `Vulnerability: ${finding.type}\nAffected JSON Key: ${key}\nPayload: ${payload}\nEvidence: ${finding.evidence}\n\nOriginal Request: ${baseRequest.getMethod()} ${baseRequest.getUrl()}`,
                                            affectedRequestId: modifiedResponse.getRequest().getId(),
                                        });
                                        caido.log.info(`[${scanId}] Issue found: ${finding.type} in JSON key ${key} with payload ${payload}`);
                                    }
                                } catch (reqError) { caido.log.warn(`[${scanId}] Error sending request (JSON body replace key ${key}): ${reqError}`); }
                                await new Promise(resolve => setTimeout(resolve, REQUEST_THROTTLE_MS));
                            }
                        }
                    }
                } catch (parseError) { caido.log.warn(`[${scanId}] Failed to parse original JSON body: ${parseError}.`); }
            }
        } 
    }
    caido.log(`PerformSingleScan finished for scanId: ${scanId}. Issues found: ${issuesFound} (from activeScanner.ts)`);
}; 