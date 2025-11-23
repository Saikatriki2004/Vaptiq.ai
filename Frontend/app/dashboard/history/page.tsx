"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow
} from "@/components/ui/table";
import { FileText, Loader2, AlertCircle, CheckCircle2, Clock, Search, Filter, Tag } from "lucide-react";
import Link from "next/link";

interface Scan {
    scan_id: string;
    status: string;
    target: {
        type: string;
        value: string;
        tags?: string[];
    };
    created_at: string;
    summary: {
        CRITICAL: number;
        HIGH: number;
        MEDIUM: number;
        LOW: number;
    };
}

export default function HistoryPage() {
    const [scans, setScans] = useState<Scan[]>([]);
    const [filteredScans, setFilteredScans] = useState<Scan[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Filters
    const [tagSearch, setTagSearch] = useState("");
    const [statusFilter, setStatusFilter] = useState("ALL");
    const [severityFilter, setSeverityFilter] = useState("ALL");

    const fetchScans = async () => {
        try {
            const response = await fetch("http://localhost:8000/scans");
            if (!response.ok) {
                throw new Error("Failed to fetch scan history");
            }
            const data = await response.json();
            setScans(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : "An error occurred");
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchScans();
        const interval = setInterval(fetchScans, 10000);
        return () => clearInterval(interval);
    }, []);

    // Apply Filters
    useEffect(() => {
        let result = scans;

        // 1. Tag Search
        if (tagSearch) {
            const searchLower = tagSearch.toLowerCase();
            result = result.filter(scan =>
                scan.target.tags?.some(tag => tag.toLowerCase().includes(searchLower)) ||
                scan.target.value.toLowerCase().includes(searchLower)
            );
        }

        // 2. Status Filter
        if (statusFilter !== "ALL") {
            result = result.filter(scan => scan.status === statusFilter);
        }

        // 3. Severity Filter
        if (severityFilter !== "ALL") {
            result = result.filter(scan => {
                if (severityFilter === "HAS_CRITICAL") return scan.summary.CRITICAL > 0;
                if (severityFilter === "HAS_HIGH") return scan.summary.HIGH > 0 || scan.summary.CRITICAL > 0;
                if (severityFilter === "HAS_ISSUES") return (scan.summary.CRITICAL + scan.summary.HIGH + scan.summary.MEDIUM + scan.summary.LOW) > 0;
                return true;
            });
        }

        setFilteredScans(result);
    }, [scans, tagSearch, statusFilter, severityFilter]);

    const getStatusBadge = (status: string) => {
        switch (status) {
            case "COMPLETED":
                return <Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 hover:bg-emerald-500/20"><CheckCircle2 className="w-3 h-3 mr-1" /> Completed</Badge>;
            case "RUNNING":
                return <Badge className="bg-blue-500/10 text-blue-500 border-blue-500/20 hover:bg-blue-500/20"><Loader2 className="w-3 h-3 mr-1 animate-spin" /> Running</Badge>;
            case "FAILED":
                return <Badge className="bg-red-500/10 text-red-500 border-red-500/20 hover:bg-red-500/20"><AlertCircle className="w-3 h-3 mr-1" /> Failed</Badge>;
            default:
                return <Badge className="bg-zinc-500/10 text-zinc-500 border-zinc-500/20 hover:bg-zinc-500/20"><Clock className="w-3 h-3 mr-1" /> {status}</Badge>;
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight text-white">Scan History</h2>
                    <p className="text-zinc-400">View and manage your past vulnerability scans.</p>
                </div>
                <Button variant="outline" onClick={() => fetchScans()}>
                    Refresh
                </Button>
            </div>

            {/* Filters Toolbar */}
            <div className="flex flex-col md:flex-row gap-4 p-4 bg-zinc-900/50 border border-zinc-800 rounded-lg">
                <div className="flex-1 relative">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-500" />
                    <Input
                        placeholder="Search targets or tags..."
                        className="pl-9 bg-zinc-950 border-zinc-800"
                        value={tagSearch}
                        onChange={(e) => setTagSearch(e.target.value)}
                    />
                </div>
                <div className="flex gap-2">
                    <Select value={statusFilter} onValueChange={setStatusFilter}>
                        <SelectTrigger className="w-[180px] bg-zinc-950 border-zinc-800">
                            <div className="flex items-center gap-2">
                                <Filter className="h-4 w-4 text-zinc-500" />
                                <SelectValue placeholder="Status" />
                            </div>
                        </SelectTrigger>
                        <SelectContent className="bg-zinc-900 border-zinc-800">
                            <SelectItem value="ALL">All Statuses</SelectItem>
                            <SelectItem value="COMPLETED">Completed</SelectItem>
                            <SelectItem value="RUNNING">Running</SelectItem>
                            <SelectItem value="FAILED">Failed</SelectItem>
                            <SelectItem value="QUEUED">Queued</SelectItem>
                        </SelectContent>
                    </Select>

                    <Select value={severityFilter} onValueChange={setSeverityFilter}>
                        <SelectTrigger className="w-[180px] bg-zinc-950 border-zinc-800">
                            <div className="flex items-center gap-2">
                                <AlertCircle className="h-4 w-4 text-zinc-500" />
                                <SelectValue placeholder="Severity" />
                            </div>
                        </SelectTrigger>
                        <SelectContent className="bg-zinc-900 border-zinc-800">
                            <SelectItem value="ALL">All Severities</SelectItem>
                            <SelectItem value="HAS_CRITICAL">Has Critical</SelectItem>
                            <SelectItem value="HAS_HIGH">Has High+</SelectItem>
                            <SelectItem value="HAS_ISSUES">Has Any Issues</SelectItem>
                        </SelectContent>
                    </Select>
                </div>
            </div>

            <Card className="bg-zinc-900 border-zinc-800">
                <CardHeader>
                    <CardTitle className="text-zinc-100">Recent Scans</CardTitle>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="flex justify-center py-8">
                            <Loader2 className="h-8 w-8 animate-spin text-emerald-500" />
                        </div>
                    ) : error ? (
                        <div className="text-center py-8 text-red-400">
                            <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                            <p>{error}</p>
                        </div>
                    ) : filteredScans.length === 0 ? (
                        <div className="text-center py-8 text-zinc-500">
                            <p>No scans found matching your filters.</p>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow className="border-zinc-800 hover:bg-zinc-800/50">
                                    <TableHead className="text-zinc-400">Target</TableHead>
                                    <TableHead className="text-zinc-400">Tags</TableHead>
                                    <TableHead className="text-zinc-400">Date</TableHead>
                                    <TableHead className="text-zinc-400">Findings</TableHead>
                                    <TableHead className="text-zinc-400">Status</TableHead>
                                    <TableHead className="text-right text-zinc-400">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {filteredScans.map((scan) => (
                                    <TableRow key={scan.scan_id} className="border-zinc-800 hover:bg-zinc-800/50">
                                        <TableCell className="font-medium text-zinc-200">
                                            <div className="flex flex-col">
                                                <span>{scan.target.value}</span>
                                                <span className="text-xs text-zinc-500">{scan.target.type}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <div className="flex flex-wrap gap-1">
                                                {scan.target.tags && scan.target.tags.length > 0 ? (
                                                    scan.target.tags.map((tag, i) => (
                                                        <Badge key={i} variant="secondary" className="text-[10px] bg-zinc-800 text-zinc-400 border-zinc-700">
                                                            {tag}
                                                        </Badge>
                                                    ))
                                                ) : (
                                                    <span className="text-zinc-600 text-xs">-</span>
                                                )}
                                            </div>
                                        </TableCell>
                                        <TableCell className="text-zinc-400 text-sm">
                                            {new Date(scan.created_at).toLocaleDateString()}
                                        </TableCell>
                                        <TableCell>
                                            <div className="flex items-center gap-2 text-xs font-mono">
                                                {scan.summary.CRITICAL > 0 && <span className="text-red-500 font-bold">{scan.summary.CRITICAL}C</span>}
                                                {scan.summary.HIGH > 0 && <span className="text-orange-500 font-bold">{scan.summary.HIGH}H</span>}
                                                {scan.summary.MEDIUM > 0 && <span className="text-yellow-500">{scan.summary.MEDIUM}M</span>}
                                                {scan.summary.LOW > 0 && <span className="text-blue-500">{scan.summary.LOW}L</span>}
                                                {(scan.summary.CRITICAL + scan.summary.HIGH + scan.summary.MEDIUM + scan.summary.LOW) === 0 && <span className="text-zinc-600">0</span>}
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            {getStatusBadge(scan.status)}
                                        </TableCell>
                                        <TableCell className="text-right">
                                            {scan.status === "COMPLETED" && (
                                                <Link href={`/dashboard/reports?scan_id=${scan.scan_id}`}>
                                                    <Button size="sm" variant="ghost" className="text-emerald-500 hover:text-emerald-400 hover:bg-emerald-500/10">
                                                        <FileText className="w-4 h-4 mr-2" />
                                                        Report
                                                    </Button>
                                                </Link>
                                            )}
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
