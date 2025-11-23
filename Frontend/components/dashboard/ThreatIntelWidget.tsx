import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, AlertCircle, ExternalLink, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const mockCVEs = [
    {
        id: "CVE-2024-9876",
        title: "Critical RCE in OpenSSL",
        severity: "CRITICAL",
        date: "2h ago",
    },
    {
        id: "CVE-2024-8721",
        title: "Privilege Escalation in Linux Kernel",
        severity: "HIGH",
        date: "5h ago",
    },
    {
        id: "CVE-2024-5543",
        title: "XSS in Apache Struts",
        severity: "MEDIUM",
        date: "1d ago",
    },
];

export function ThreatIntelWidget() {
    const [cves, setCves] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchCVEs = async () => {
        setLoading(true);
        try {
            const res = await fetch("http://localhost:8000/cves");
            if (res.ok) {
                const data = await res.json();
                setCves(data);
            }
        } catch (error) {
            console.error("Failed to fetch CVEs", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchCVEs();
    }, []);

    return (
        <Card className="bg-zinc-900 border-t-2 border-t-blue-500 border-x-zinc-800 border-b-zinc-800 h-full">
            <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium text-zinc-400 flex items-center gap-2">
                        <Shield className="h-4 w-4 text-blue-500" />
                        Live Threat Intelligence
                    </CardTitle>
                    <div className="flex items-center gap-2">
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6 text-zinc-500 hover:text-white"
                            onClick={fetchCVEs}
                        >
                            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
                        </Button>
                        <Badge variant="outline" className="text-blue-500 border-blue-500/20 bg-blue-500/10">
                            Live
                        </Badge>
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <Tabs defaultValue="global" className="w-full">
                    <TabsList className="grid w-full grid-cols-2 bg-zinc-950">
                        <TabsTrigger value="global">Global Feed</TabsTrigger>
                        <TabsTrigger value="context">Context Alerts</TabsTrigger>
                    </TabsList>
                    <TabsContent value="global" className="mt-4 space-y-4 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                        {loading ? (
                            <div className="flex justify-center py-8">
                                <RefreshCw className="h-6 w-6 animate-spin text-blue-500" />
                            </div>
                        ) : cves.length === 0 ? (
                            <div className="text-center py-8 text-zinc-500">
                                <p>Unable to load feed.</p>
                            </div>
                        ) : (
                            cves.map((cve, idx) => (
                                <div key={idx} className="flex items-start justify-between border-b border-zinc-800 pb-3 last:border-0 group">
                                    <div className="flex-1 mr-4">
                                        <div className="flex items-center gap-2 mb-1">
                                            <a
                                                href={cve.link}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-xs font-mono text-blue-400 hover:underline flex items-center gap-1"
                                            >
                                                {cve.id}
                                                <ExternalLink className="h-2 w-2 opacity-0 group-hover:opacity-100 transition-opacity" />
                                            </a>
                                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${cve.severity === "CRITICAL" ? "bg-red-500/10 text-red-500" :
                                                cve.severity === "HIGH" ? "bg-orange-500/10 text-orange-500" :
                                                    "bg-yellow-500/10 text-yellow-500"
                                                }`}>
                                                {cve.severity}
                                            </span>
                                        </div>
                                        <p className="text-sm text-zinc-300 line-clamp-2" title={cve.title}>{cve.title}</p>
                                    </div>
                                    <span className="text-xs text-zinc-500 whitespace-nowrap">{new Date(cve.date).toLocaleDateString()}</span>
                                </div>
                            ))
                        )}
                    </TabsContent>
                    <TabsContent value="context" className="mt-4">
                        <div className="flex flex-col items-center justify-center py-8 text-center">
                            <div className="h-12 w-12 rounded-full bg-emerald-500/10 flex items-center justify-center mb-3">
                                <Shield className="h-6 w-6 text-emerald-500" />
                            </div>
                            <h4 className="text-sm font-medium text-white">No Active Threats</h4>
                            <p className="text-xs text-zinc-500 mt-1 max-w-[200px]">
                                No immediate threats detected matching your current target profile.
                            </p>
                        </div>
                    </TabsContent>
                </Tabs>
            </CardContent>
        </Card>
    );
}
