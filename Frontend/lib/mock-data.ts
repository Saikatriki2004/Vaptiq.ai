// apps/web/lib/mock-data.ts

import { ScanResult } from "@/components/scan-log-viewer";

export const mockScanResult: ScanResult = {
    target: "https://example.com/api/v1",
    duration_seconds: 45.72,
    logs: [
        {
            timestamp: new Date(Date.now() - 45000).toISOString(),
            step: "RECON",
            message: "Initiating passive scan on https://example.com/api/v1...",
        },
        {
            timestamp: new Date(Date.now() - 42000).toISOString(),
            step: "RECON",
            message: "Parsing OpenAPI schema definition...",
        },
        {
            timestamp: new Date(Date.now() - 38000).toISOString(),
            step: "ATTACK_PLAN",
            message: "Formulating attack vectors based on recon data...",
        },
        {
            timestamp: new Date(Date.now() - 35000).toISOString(),
            step: "EXECUTION",
            message: "Fuzzing Auth headers on /users/{id}...",
        },
        {
            timestamp: new Date(Date.now() - 30000).toISOString(),
            step: "EXECUTION",
            message: "Discovered potential BOLA vulnerability on GET /users/{id}...",
        },
        {
            timestamp: new Date(Date.now() - 25000).toISOString(),
            step: "REPORTING",
            message: "Compiling evidence for BOLA vulnerability.",
        },
        {
            timestamp: new Date(Date.now() - 20000).toISOString(),
            step: "EXECUTION",
            message: "Testing for SQL Injection on POST /login...",
        },
        {
            timestamp: new Date(Date.now() - 15000).toISOString(),
            step: "REPORTING",
            message: "No immediate SQLi found, further manual review recommended.",
        },
        {
            timestamp: new Date(Date.now() - 10000).toISOString(),
            step: "EXECUTION",
            message: "Probing for exposed API keys in environment variables...",
        },
        {
            timestamp: new Date(Date.now() - 5000).toISOString(),
            step: "ERROR",
            message: "Failed to connect to internal endpoint: Timeout after 5s.",
        },
        {
            timestamp: new Date(Date.now() - 2000).toISOString(),
            step: "REPORTING",
            message: "Finalizing scan report with discovered vulnerabilities.",
        },
    ],
    vulnerabilities: [
        {
            title: "Broken Object Level Authorization (BOLA)",
            severity: "CRITICAL",
            description:
                "An unprivileged user could access/modify resources belonging to other users by simply changing the ID in the API request URL.",
            remediation:
                "Implement robust authorization checks at every endpoint to verify resource ownership.",
        },
        {
            title: "Exposed Internal Endpoint",
            severity: "HIGH",
            description:
                "An internal API endpoint /admin/metrics was exposed to the public internet.",
            remediation:
                "Restrict access to internal endpoints using network ACLs or API Gateway policies.",
        },
        {
            title: "Missing Rate Limiting on Login",
            severity: "MEDIUM",
            description: "The /login endpoint does not have rate limiting, allowing for brute-force attacks.",
            remediation: "Implement rate limiting (e.g., 5 attempts per minute per IP) on authentication endpoints.",
        },
    ],
};

export const mockEmptyScanResult: ScanResult = {
    target: "https://secure-app.com",
    duration_seconds: 12.34,
    logs: [
        {
            timestamp: new Date(Date.now() - 12000).toISOString(),
            step: "RECON",
            message: "Initiating scan on https://secure-app.com...",
        },
        {
            timestamp: new Date(Date.now() - 8000).toISOString(),
            step: "EXECUTION",
            message: "Running standard web vulnerability checks...",
        },
        {
            timestamp: new Date(Date.now() - 4000).toISOString(),
            step: "REPORTING",
            message: "No immediate vulnerabilities found.",
        },
    ],
    vulnerabilities: [],
};

// Legacy mock data (kept for backward compatibility)
export interface Vulnerability {
    id: string;
    title: string;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    description: string;
    remediation: string;
}

export interface ScanLog {
    id: string;
    message: string;
    timestamp: string;
}

export const MOCK_VULNERABILITIES: Vulnerability[] = [
    {
        id: "v1",
        title: "OpenSSH 7.2 Vulnerability",
        severity: "HIGH",
        description: "The remote SSH server is affected by a security bypass vulnerability.",
        remediation: "Upgrade to OpenSSH 7.3 or later.",
    },
    {
        id: "v2",
        title: "Missing CSRF Token",
        severity: "MEDIUM",
        description: "The web application does not enforce CSRF tokens on state-changing forms.",
        remediation: "Implement Anti-CSRF tokens in all POST forms.",
    },
    {
        id: "v3",
        title: "SQL Injection in /api/login",
        severity: "CRITICAL",
        description: "The 'username' parameter is vulnerable to SQL injection.",
        remediation: "Use parameterized queries or an ORM.",
    },
    {
        id: "v4",
        title: "Information Disclosure",
        severity: "LOW",
        description: "Server banner reveals version information.",
        remediation: "Configure the server to hide version details.",
    },
];

export const MOCK_LOGS: ScanLog[] = [
    { id: "l1", message: "Agent initialized.", timestamp: "10:00:01" },
    { id: "l2", message: "Target identified as URL.", timestamp: "10:00:02" },
    { id: "l3", message: "Starting Web Crawler tool...", timestamp: "10:00:03" },
    { id: "l4", message: "Crawling /login...", timestamp: "10:00:05" },
    { id: "l5", message: "Found potential vulnerability: Missing CSRF Token", timestamp: "10:00:08" },
    { id: "l6", message: "Scan completed.", timestamp: "10:00:15" },
];
