// apps/web/components/scan-log-viewer.tsx
"use client";

import React, { useEffect, useRef } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import {
    Table,
    TableHeader,
    TableRow,
    TableHead,
    TableBody,
    TableCell,
} from "@/components/ui/table";

// --- Type Definitions (Ensure these match your backend Pydantic models) ---
export interface AgentLog {
    timestamp: string;
    step: string;
    message: string;
}

export interface Vulnerability {
    title: string;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    description: string;
    remediation: string;
}

export interface ScanResult {
    target: string;
    duration_seconds: number;
    logs: AgentLog[];
    vulnerabilities: Vulnerability[];
}

interface ScanLogViewerProps {
    scanResult: ScanResult | null; // Can be null while loading
    isLoading: boolean;
    error: string | null;
}

const getSeverityColor = (severity: Vulnerability["severity"]) => {
    switch (severity) {
        case "CRITICAL":
            return "bg-red-600 text-red-50";
        case "HIGH":
            return "bg-orange-500 text-orange-50";
        case "MEDIUM":
            return "bg-yellow-400 text-yellow-950";
        case "LOW":
            return "bg-green-500 text-green-50";
        default:
            return "bg-gray-400 text-gray-950";
    }
};

export function ScanLogViewer({
    scanResult,
    isLoading,
    error,
}: ScanLogViewerProps) {
    const scrollAreaRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to bottom as new logs appear
    useEffect(() => {
        if (scrollAreaRef.current) {
            scrollAreaRef.current.scrollTop = scrollAreaRef.current.scrollHeight;
        }
    }, [scanResult?.logs.length]);

    if (isLoading) {
        return (
            <Card className="w-full h-[600px] bg-slate-950 text-emerald-500 border-emerald-800">
                <CardHeader className="border-b border-emerald-800">
                    <CardTitle className="text-emerald-400">
                        Initializing Scan...
                    </CardTitle>
                </CardHeader>
                <CardContent className="flex items-center justify-center h-[calc(100%-72px)]">
                    <p className="text-xl animate-pulse">
                        Establishing secure connection and deploying agent...
                    </p>
                </CardContent>
            </Card>
        );
    }

    if (error) {
        return (
            <Card className="w-full h-[600px] bg-red-950 text-red-300 border-red-700">
                <CardHeader className="border-b border-red-700">
                    <CardTitle className="text-red-400">Scan Error</CardTitle>
                </CardHeader>
                <CardContent className="flex items-center justify-center h-[calc(100%-72px)]">
                    <p className="text-lg">{error}</p>
                </CardContent>
            </Card>
        );
    }

    if (!scanResult) {
        return (
            <Card className="w-full h-[600px] bg-slate-950 text-emerald-500 border-emerald-800">
                <CardHeader className="border-b border-emerald-800">
                    <CardTitle className="text-emerald-400">
                        Awaiting Scan Start
                    </CardTitle>
                </CardHeader>
                <CardContent className="flex items-center justify-center h-[calc(100%-72px)]">
                    <p className="text-xl">Submit a target to begin an agentic scan.</p>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card className="w-full h-[600px] bg-slate-950 text-emerald-500 border-emerald-800 flex flex-col">
            <CardHeader className="border-b border-emerald-800 flex flex-row items-center justify-between">
                <CardTitle className="text-emerald-400">
                    Scan Report: {scanResult.target}
                </CardTitle>
                <Badge
                    className={
                        scanResult.logs.some((log) => log.step === "ERROR")
                            ? "bg-red-600 hover:bg-red-600"
                            : "bg-emerald-600 hover:bg-emerald-600"
                    }
                >
                    {scanResult.logs.some((log) => log.step === "ERROR")
                        ? "FAILED"
                        : "COMPLETED"}
                </Badge>
            </CardHeader>
            <CardContent className="flex-grow p-0 overflow-hidden">
                <div className="grid md:grid-cols-2 h-full">
                    {/* Agent Logs (Terminal View) */}
                    <div className="flex flex-col border-r border-emerald-800 p-4">
                        <h3 className="text-lg font-semibold mb-2 text-emerald-300">
                            Agent Activity
                        </h3>
                        <ScrollArea className="flex-grow pr-4" ref={scrollAreaRef}>
                            {scanResult.logs.map((log, index) => (
                                <div key={index} className="flex text-sm mb-1 font-mono">
                                    <span className="text-emerald-700 w-24 flex-shrink-0">
                                        [{log.timestamp.split("T")[1].split(".")[0]}]
                                    </span>
                                    <span
                                        className={`font-bold w-20 flex-shrink-0 ${log.step === "ERROR" ? "text-red-500" : "text-emerald-400"
                                            }`}
                                    >
                                        {log.step}:
                                    </span>
                                    <span
                                        className={`${log.step === "ERROR" ? "text-red-300" : "text-emerald-100"
                                            } flex-grow`}
                                    >
                                        {log.message}
                                    </span>
                                </div>
                            ))}
                        </ScrollArea>
                    </div>

                    {/* Vulnerabilities Table */}
                    <div className="flex flex-col p-4">
                        <h3 className="text-lg font-semibold mb-2 text-emerald-300">
                            Discovered Vulnerabilities ({scanResult.vulnerabilities.length})
                        </h3>
                        <ScrollArea className="flex-grow pr-4">
                            {scanResult.vulnerabilities.length === 0 ? (
                                <p className="text-emerald-300 text-center mt-8">
                                    No vulnerabilities found. Great job!
                                </p>
                            ) : (
                                <Table>
                                    <TableHeader>
                                        <TableRow className="border-emerald-800 hover:bg-slate-900">
                                            <TableHead className="w-[120px] text-emerald-300">
                                                Severity
                                            </TableHead>
                                            <TableHead className="text-emerald-300">Title</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {scanResult.vulnerabilities.map((vuln, index) => (
                                            <TableRow
                                                key={index}
                                                className="border-emerald-900 hover:bg-slate-800"
                                            >
                                                <TableCell>
                                                    <Badge className={getSeverityColor(vuln.severity)}>
                                                        {vuln.severity}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell className="font-medium text-emerald-100">
                                                    {vuln.title}
                                                    <p className="text-xs text-emerald-300 mt-1 line-clamp-2">
                                                        {vuln.description}
                                                    </p>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            )}
                        </ScrollArea>
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
