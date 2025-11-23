"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { FileText, Download, Code, FileJson, File, CheckCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";

// Mock Data for Reports
const reports = [
    {
        id: "scan_123",
        target: "https://example.com",
        date: "2024-05-21",
        findings: 17,
        status: "Completed",
    },
    {
        id: "scan_124",
        target: "192.168.1.105",
        date: "2024-05-20",
        findings: 5,
        status: "Completed",
    },
    {
        id: "scan_125",
        target: "api.stripe.com",
        date: "2024-05-19",
        findings: 0,
        status: "Failed",
    },
];

const BACKEND_URL = "http://localhost:8000";

export default function ReportsPage() {
    const [selectedScan, setSelectedScan] = useState<string | null>(null);
    const [format, setFormat] = useState("pdf");
    const [severities, setSeverities] = useState({
        CRITICAL: true,
        HIGH: true,
        MEDIUM: true,
        LOW: true
    });
    const [isDialogOpen, setIsDialogOpen] = useState(false);

    const handleOpenDialog = (scanId: string) => {
        setSelectedScan(scanId);
        setIsDialogOpen(true);
    };

    const toggleSeverity = (sev: keyof typeof severities) => {
        setSeverities(prev => ({ ...prev, [sev]: !prev[sev] }));
    };

    const toggleSelectAll = () => {
        const allSelected = Object.values(severities).every(Boolean);
        setSeverities({
            CRITICAL: !allSelected,
            HIGH: !allSelected,
            MEDIUM: !allSelected,
            LOW: !allSelected
        });
    };

    const handleDownload = async () => {
        if (!selectedScan) return;

        try {
            const activeSeverities = Object.entries(severities)
                .filter(([_, isActive]) => isActive)
                .map(([sev]) => sev)
                .join(",");

            const response = await fetch(`${BACKEND_URL}/scan/${selectedScan}/export?format=${format}&severities=${activeSeverities}`);
            if (!response.ok) throw new Error("Download failed");

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `vaptiq_report_${selectedScan}.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            setIsDialogOpen(false);
        } catch (error) {
            console.error("Export error:", error);
            alert("Failed to download report. Please try again.");
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight text-white">Reports & Archives</h2>
                    <p className="text-zinc-400">Export detailed security assessments and audit logs.</p>
                </div>
            </div>

            <Card className="bg-zinc-900 border-zinc-800">
                <CardHeader>
                    <CardTitle className="text-zinc-200">Scan History</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="rounded-md border border-zinc-800">
                        <table className="w-full text-sm text-left">
                            <thead className="bg-zinc-950 text-zinc-400 font-medium border-b border-zinc-800">
                                <tr>
                                    <th className="px-4 py-3">Target Asset</th>
                                    <th className="px-4 py-3">Date</th>
                                    <th className="px-4 py-3">Findings</th>
                                    <th className="px-4 py-3">Status</th>
                                    <th className="px-4 py-3 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800">
                                {reports.map((report) => (
                                    <tr key={report.id} className="hover:bg-zinc-800/50 transition-colors">
                                        <td className="px-4 py-3 font-medium text-white">{report.target}</td>
                                        <td className="px-4 py-3 text-zinc-500">{report.date}</td>
                                        <td className="px-4 py-3">
                                            <Badge variant="outline" className={
                                                report.findings > 10 ? "text-red-400 border-red-400/20 bg-red-400/10" :
                                                    report.findings > 0 ? "text-orange-400 border-orange-400/20 bg-orange-400/10" :
                                                        "text-emerald-400 border-emerald-400/20 bg-emerald-400/10"
                                            }>
                                                {report.findings} Issues
                                            </Badge>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${report.status === "Completed" ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500"
                                                }`}>
                                                {report.status}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                className="border-zinc-700 text-zinc-300 hover:text-white hover:bg-zinc-800"
                                                onClick={() => handleOpenDialog(report.id)}
                                            >
                                                <Download className="mr-2 h-4 w-4" />
                                                Export
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </CardContent>
            </Card>

            {/* Report Configuration Dialog */}
            {isDialogOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
                    <div className="bg-zinc-900 border border-zinc-800 rounded-lg shadow-lg w-full max-w-md p-6 space-y-4">
                        <div className="flex items-center justify-between">
                            <h3 className="text-lg font-semibold text-white">Export Configuration</h3>
                            <Button variant="ghost" size="sm" onClick={() => setIsDialogOpen(false)} className="text-zinc-500 hover:text-white">✕</Button>
                        </div>

                        <div className="space-y-4">
                            <div className="space-y-2">
                                <label className="text-sm font-medium text-zinc-400">Format</label>
                                <div className="flex gap-2">
                                    {['pdf', 'html', 'json'].map((fmt) => (
                                        <Button
                                            key={fmt}
                                            variant={format === fmt ? "default" : "outline"}
                                            onClick={() => setFormat(fmt)}
                                            className={`flex-1 uppercase ${format === fmt ? 'bg-blue-600 hover:bg-blue-700' : 'border-zinc-700 text-zinc-300'}`}
                                        >
                                            {fmt}
                                        </Button>
                                    ))}
                                </div>
                            </div>

                            <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                    <label className="text-sm font-medium text-zinc-400">Filter by Severity</label>
                                    <Button
                                        variant="link"
                                        size="sm"
                                        onClick={toggleSelectAll}
                                        className="text-blue-400 h-auto p-0 text-xs"
                                    >
                                        {Object.values(severities).every(Boolean) ? "Deselect All" : "Select All"}
                                    </Button>
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                    {Object.entries(severities).map(([sev, isActive]) => (
                                        <div
                                            key={sev}
                                            onClick={() => toggleSeverity(sev as any)}
                                            className={`flex items-center gap-2 p-2 rounded border cursor-pointer transition-colors ${isActive
                                                ? 'bg-blue-500/10 border-blue-500/50'
                                                : 'bg-zinc-950 border-zinc-800 hover:bg-zinc-900'
                                                }`}
                                        >
                                            <div className={`w-4 h-4 rounded border flex items-center justify-center ${isActive ? 'bg-blue-500 border-blue-500' : 'border-zinc-600'
                                                }`}>
                                                {isActive && <CheckCircle2 className="w-3 h-3 text-white" />}
                                            </div>
                                            <span className={`text-sm ${isActive ? 'text-white' : 'text-zinc-400'}`}>{sev}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="flex justify-end gap-2 pt-2">
                            <Button variant="ghost" onClick={() => setIsDialogOpen(false)} className="text-zinc-400 hover:text-white">Cancel</Button>
                            <Button onClick={handleDownload} className="bg-blue-600 hover:bg-blue-700 text-white">
                                <Download className="w-4 h-4 mr-2" />
                                Download Report
                            </Button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
