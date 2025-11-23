"use client";

import { useState } from "react";
import { KPICards } from "@/components/dashboard/KPICards";
import { ThreatIntelWidget } from "@/components/dashboard/ThreatIntelWidget";
import { ScanProgress } from "@/components/dashboard/ScanProgress";
import { VulnChart } from "@/components/dashboard/VulnChart";
import { Button } from "@/components/ui/button";
import { Plus } from "lucide-react";
import { ScanLogViewer } from "@/components/scan-log-viewer";
import { mockScanResult } from "@/lib/mock-data";

// Re-using existing logic for demo purposes
const BACKEND_URL = "http://localhost:8000";

export default function DashboardPage() {
    const [isScanning, setIsScanning] = useState(false);

    return (
        <div className="space-y-6">
            {/* Header Actions */}
            <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold tracking-tight text-white">Overview</h2>
                <div className="flex items-center space-x-2">
                    <Button className="bg-emerald-600 hover:bg-emerald-700 text-white">
                        <Plus className="mr-2 h-4 w-4" />
                        New Scan
                    </Button>
                </div>
            </div>

            {/* Row 1: KPI Cards */}
            <KPICards />

            {/* Row 2: Charts & Intel */}
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-7">
                <div className="col-span-3">
                    <VulnChart />
                </div>
                <div className="col-span-4">
                    <ThreatIntelWidget />
                </div>
            </div>

            {/* Row 3: Active Scans & Logs */}
            <div className="grid gap-6 md:grid-cols-1">
                <ScanProgress />

                {/* Legacy Log Viewer Integration */}
                <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
                    <div className="p-4 border-b border-zinc-800">
                        <h3 className="font-medium text-zinc-200">Recent Scan Logs</h3>
                    </div>
                    <div className="p-0">
                        <ScanLogViewer
                            scanResult={mockScanResult}
                            isLoading={false}
                            error={null}
                        />
                    </div>
                </div>
            </div>
        </div>
    );
}
