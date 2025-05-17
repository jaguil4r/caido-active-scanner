// backend/passive.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HttpResponse, HttpRequest, QueryParameter } from '@caido/sdk-backend'; // Mock or use actual types

// Import the functions to test
import {
    checkMissingSecurityHeaders,
    checkReflectedParameters,
    checkServerVersionDisclosure
} from './index'; // Adjust path if necessary

// --- Mocking Caido SDK Objects ---

const createMockRequest = (queryParams: QueryParameter[] = [], headers: Record<string, string> = {}): HttpRequest => {
    return {
        getId: () => 'req-test-123',
        getQueryParameters: () => queryParams,
        getHeader: (name: string) => headers[name.toLowerCase()],
        // Add other methods as needed by checks
    } as unknown as HttpRequest;
};

const createMockResponse = (headers: Record<string, string>, body: string = '', request?: HttpRequest): HttpResponse => {
    const req = request || createMockRequest();
    return {
        getRequest: () => req,
        getHeaders: () => headers,
        getBodyAsString: () => body,
        // Add other methods as needed by checks
    } as unknown as HttpResponse;
};

// --- Test Suite ---
describe('Passive Scanner Helper Functions', () => {

    describe('checkMissingSecurityHeaders', () => {
        it('should return empty array when all required headers are present and correct', () => {
            const headers = {
                'Strict-Transport-Security': 'max-age=31536000',
                'Content-Security-Policy': "default-src 'self'",
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'Permissions-Policy': 'geolocation=(), microphone=()',
            };
            const mockResponse = createMockResponse(headers);
            const findings = checkMissingSecurityHeaders(mockResponse);
            expect(findings).toEqual([]);
        });

        it('should identify multiple missing security headers', () => {
            const headers = {
                'x-frame-options': 'SAMEORIGIN', // Present but others missing
            };
            const mockResponse = createMockResponse(headers);
            const findings = checkMissingSecurityHeaders(mockResponse);
            expect(findings).toEqual(expect.arrayContaining([
                'Missing security header: strict-transport-security',
                'Missing security header: content-security-policy',
                'Missing security header: referrer-policy',
                'Missing security header: permissions-policy',
                'Missing security header: x-content-type-options',
            ]));
            expect(findings.length).toBe(5);
        });

        it('should identify insecure x-content-type-options value', () => {
            const headers = {
                'X-Content-Type-Options': 'sniff' // Insecure value
            };
            const mockResponse = createMockResponse(headers);
            const findings = checkMissingSecurityHeaders(mockResponse);
             // It will also report the other missing headers
            expect(findings).toEqual(expect.arrayContaining([
                'Insecure value for x-content-type-options: "sniff". Expected "nosniff".'
            ]));
        });
    });

    describe('checkReflectedParameters', () => {
        it('should identify a reflected query parameter', () => {
            const queryParams = [{ name: 'search', value: 'test-value' }];
            const request = createMockRequest(queryParams);
            const responseBody = '<html><body>Search results for test-value here.</body></html>';
            const mockResponse = createMockResponse({}, responseBody, request);
            const findings = checkReflectedParameters(request, mockResponse);
            expect(findings).toEqual(['search']);
        });

        it('should identify multiple reflected query parameters', () => {
            const queryParams = [
                { name: 'user', value: 'admin' }, 
                { name: 'id', value: '12345' }
            ];
            const request = createMockRequest(queryParams);
            const responseBody = 'User: admin, ID: 12345';
            const mockResponse = createMockResponse({}, responseBody, request);
            const findings = checkReflectedParameters(request, mockResponse);
            expect(findings).toEqual(expect.arrayContaining(['user', 'id']));
            expect(findings.length).toBe(2);
        });

        it('should not identify reflection if parameter value is not in response', () => {
            const queryParams = [{ name: 'search', value: 'test-value' }];
            const request = createMockRequest(queryParams);
            const responseBody = '<html><body>No results found.</body></html>';
            const mockResponse = createMockResponse({}, responseBody, request);
            const findings = checkReflectedParameters(request, mockResponse);
            expect(findings).toEqual([]);
        });

        it('should ignore very short or very long reflections to reduce FPs', () => {
             const queryParams = [
                { name: 'short', value: 'a' }, // Too short
                { name: 'long', value: 'a'.repeat(150) }, // Too long
                { name: 'ok', value: 'goodvalue' },
             ];
            const request = createMockRequest(queryParams);
            const responseBody = `Reflected: a ${'a'.repeat(150)} goodvalue`;
            const mockResponse = createMockResponse({}, responseBody, request);
            const findings = checkReflectedParameters(request, mockResponse);
            expect(findings).toEqual(['ok']);
        });
        
        // TODO: Add test case for reflected body parameters once implemented
    });

    describe('checkServerVersionDisclosure', () => {
        it('should identify version disclosure in Server header', () => {
            const headers = { 'Server': 'Apache/2.4.52 (Ubuntu)' };
            const mockResponse = createMockResponse(headers);
            const findings = checkServerVersionDisclosure(mockResponse);
            expect(findings).toEqual(['Potential version disclosure via header: server: Apache/2.4.52 (Ubuntu)']);
        });

        it('should identify version disclosure in X-Powered-By header', () => {
            const headers = { 'X-Powered-By': 'PHP/8.1.2' };
            const mockResponse = createMockResponse(headers);
            const findings = checkServerVersionDisclosure(mockResponse);
            expect(findings).toEqual(['Potential version disclosure via header: x-powered-by: PHP/8.1.2']);
        });

        it('should identify version disclosure in X-AspNet-Version header', () => {
            const headers = { 'X-AspNet-Version': '4.0.30319' };
            const mockResponse = createMockResponse(headers);
            const findings = checkServerVersionDisclosure(mockResponse);
            expect(findings).toEqual(['Potential version disclosure via header: x-aspnet-version: 4.0.30319']);
        });

        it('should not identify disclosure for generic server names', () => {
            const headers = { 'Server': 'Apache' }; // Too generic
            const mockResponse = createMockResponse(headers);
            const findings = checkServerVersionDisclosure(mockResponse);
            expect(findings).toEqual([]);
        });

        it('should not identify disclosure if no version number is present', () => {
            const headers = { 'X-Powered-By': 'Express' };
            const mockResponse = createMockResponse(headers);
            const findings = checkServerVersionDisclosure(mockResponse);
            expect(findings).toEqual([]);
        });

        it('should handle case-insensitivity for header names', () => {
             const headers = { 'sErVeR': 'nginx/1.21.6' };
            const mockResponse = createMockResponse(headers);
            const findings = checkServerVersionDisclosure(mockResponse);
            expect(findings).toEqual(['Potential version disclosure via header: server: nginx/1.21.6']);
        });
    });

    // Removed old integration test block - prefer testing helpers directly for now.
    // Integration tests for runPassiveChecks could be added later, likely mocking the helpers.
}); 