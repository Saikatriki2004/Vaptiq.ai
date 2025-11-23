"use client";

import { useState, useCallback, useEffect } from "react";
import ReactFlow, {
    Node,
    Edge,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    Connection,
    addEdge,
    MarkerType,
    Position,
} from "reactflow";
import "reactflow/dist/style.css";
import dagre from "dagre";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, ShieldAlert, Network, RefreshCw, Loader2 } from "lucide-react";

// Dagre layout configuration
const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = 'TB') => {
    const dagreGraph = new dagre.graphlib.Graph();
    dagreGraph.setDefaultEdgeLabel(() => ({}));
    dagreGraph.setGraph({ rankdir: direction, nodesep: 80, ranksep: 120 });

    nodes.forEach((node) => {
        dagreGraph.setNode(node.id, { width: 200, height: 80 });
    });

    edges.forEach((edge) => {
        dagreGraph.setEdge(edge.source, edge.target);
    });

    dagre.layout(dagreGraph);

    const layoutedNodes = nodes.map((node) => {
        const nodeWithPosition = dagreGraph.node(node.id);
        return {
            ...node,
            position: {
                x: nodeWithPosition.x - 100,
                y: nodeWithPosition.y - 40,
            },
            sourcePosition: Position.Bottom,
            targetPosition: Position.Top,
        };
    });

    return { nodes: layoutedNodes, edges };
};

const initialNodes: Node[] = [
    {
        id: "start",
        type: "input",
        data: { label: "🌐 Internet" },
        position: { x: 250, y: 0 },
        style: {
            background: "linear-gradient(135deg, #1e293b 0%, #0f172a 100%)",
            color: "#fff",
            border: "2px solid #3b82f6",
            borderRadius: "8px",
            padding: "12px",
            fontSize: "14px",
            fontWeight: "600"
        },
    },
];

const initialEdges: Edge[] = [];

const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
        case "CRITICAL": return { bg: "#450a0a", border: "#dc2626", glow: "#ef4444" };
        case "HIGH": return { bg: "#7c2d12", border: "#ea580c", glow: "#fb923c" };
        case "MEDIUM": return { bg: "#713f12", border: "#ca8a04", glow: "#fbbf24" };
        default: return { bg: "#1e293b", border: "#475569", glow: "#64748b" };
    }
};

export default function AttackPathsPage() {
    const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState<any[]>([]);
    const [selectedScan, setSelectedScan] = useState<string>("");
    const [loadingScans, setLoadingScans] = useState(true);

    const onConnect = useCallback(
        (params: Connection) => setEdges((eds: Edge[]) => addEdge(params, eds)),
        [setEdges]
    );

    // Fetch available scans
    useEffect(() => {
        const fetchScans = async () => {
            try {
                const response = await fetch("http://localhost:8000/scans");
                if (response.ok) {
                    const data = await response.json();
                    const completedScans = data.filter((s: any) => s.status === "COMPLETED");
                    setScans(completedScans);
                    if (completedScans.length > 0) {
                        setSelectedScan(completedScans[0].scan_id);
                    }
                }
            } catch (error) {
                console.error("Failed to fetch scans:", error);
            } finally {
                setLoadingScans(false);
            }
        };
        fetchScans();
    }, []);

    const simulateAttack = async () => {
        if (!selectedScan) {
            alert("Please select a scan first");
            return;
        }

        setLoading(true);
        try {
            const response = await fetch(`http://localhost:8000/scan/${selectedScan}/simulate-attack`, {
                method: "POST",
            });

            if (!response.ok) throw new Error("Simulation failed");

            const graph = await response.json();

            // Transform backend graph to ReactFlow format with enhanced styling
            const newNodes: Node[] = graph.nodes.map((n: any) => {
                const colors = n.type === "technique"
                    ? { bg: "#7f1d1d", border: "#ef4444", glow: "#dc2626" }
                    : n.type === "goal"
                        ? { bg: "#4c1d95", border: "#a78bfa", glow: "#8b5cf6" }
                        : n.severity
                            ? getSeverityColor(n.severity)
                            : { bg: "#1e293b", border: "#475569", glow: "#64748b" };

                return {
                    id: n.id,
                    type: n.type === "start" ? "input" : n.type === "goal" ? "output" : "default",
                    data: {
                        label: (
                            <div className="text-center">
                                <div className="font-semibold">{n.label}</div>
                                {n.mitre_id && <div className="text-xs text-zinc-400 mt-1">{n.mitre_id}</div>}
                                {n.severity && <div className={`text-xs mt-1 font-bold ${n.severity === "CRITICAL" ? "text-red-400" :
                                        n.severity === "HIGH" ? "text-orange-400" :
                                            "text-yellow-400"
                                    }`}>{n.severity}</div>}
                            </div>
                        )
                    },
                    position: { x: 0, y: 0 },
                    style: {
                        background: colors.bg,
                        color: "#fff",
                        border: `2px solid ${colors.border}`,
                        borderRadius: "8px",
                        padding: "12px",
                        boxShadow: `0 0 20px ${colors.glow}40`,
                        width: 200,
                        fontSize: "13px"
                    },
                };
            });

            const newEdges: Edge[] = graph.edges.map((e: any, index: number) => ({
                id: `e${index}`,
                source: e.source,
                target: e.target,
                label: e.description,
                animated: true,
                style: { stroke: "#ef4444", strokeWidth: 2 },
                labelStyle: { fill: "#a1a1aa", fontSize: 11 },
                labelBgStyle: { fill: "#18181b", fillOpacity: 0.8 },
                markerEnd: { type: MarkerType.ArrowClosed, color: "#ef4444", width: 20, height: 20 },
            }));

            // Apply dagre layout
            const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(newNodes, newEdges);
            setNodes(layoutedNodes);
            setEdges(layoutedEdges);

        } catch (error) {
            console.error("Simulation error:", error);
            alert("Failed to run simulation. Ensure backend is running.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-100px)]">
            {/* Left Panel: Controls & Info */}
            <Card className="bg-zinc-900 border-zinc-800 lg:col-span-1">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-emerald-500">
                        <Network className="h-5 w-5" />
                        Attack Path Simulation
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                    <div className="p-4 bg-zinc-950/50 rounded-lg border border-zinc-800">
                        <h3 className="text-zinc-100 font-medium mb-2">Simulation Engine</h3>
                        <p className="text-sm text-zinc-400 mb-4">
                            Uses Hybrid AI/Static analysis to map confirmed vulnerabilities to MITRE ATT&CK techniques and predict potential kill chains.
                        </p>

                        {/* Scan Selector */}
                        <div className="mb-4">
                            <label className="text-sm text-zinc-400 mb-2 block">Select Scan</label>
                            {loadingScans ? (
                                <div className="flex items-center justify-center py-2">
                                    <Loader2 className="h-4 w-4 animate-spin text-emerald-500" />
                                </div>
                            ) : scans.length === 0 ? (
                                <p className="text-xs text-zinc-500">No completed scans available</p>
                            ) : (
                                <Select value={selectedScan} onValueChange={setSelectedScan}>
                                    <SelectTrigger className="bg-zinc-900 border-zinc-700">
                                        <SelectValue placeholder="Choose a scan" />
                                    </SelectTrigger>
                                    <SelectContent className="bg-zinc-900 border-zinc-800">
                                        {scans.map((scan) => (
                                            <SelectItem key={scan.scan_id} value={scan.scan_id}>
                                                {scan.target.value} - {new Date(scan.created_at).toLocaleDateString()}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            )}
                        </div>

                        <Button
                            onClick={simulateAttack}
                            disabled={loading || !selectedScan}
                            className="w-full bg-emerald-600 hover:bg-emerald-700 text-white"
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Simulating...
                                </>
                            ) : (
                                <>
                                    <Play className="mr-2 h-4 w-4" /> Run Simulation
                                </>
                            )}
                        </Button>
                    </div>

                    <div className="space-y-3">
                        <h4 className="text-sm font-medium text-zinc-300">Legend</h4>
                        <div className="flex items-center gap-2 text-sm text-zinc-400">
                            <div className="w-4 h-4 bg-blue-900 border-2 border-blue-500 rounded"></div> Entry Point
                        </div>
                        <div className="flex items-center gap-2 text-sm text-zinc-400">
                            <div className="w-4 h-4 bg-zinc-700 border-2 border-red-500 rounded"></div> Critical Vuln
                        </div>
                        <div className="flex items-center gap-2 text-sm text-zinc-400">
                            <div className="w-4 h-4 bg-red-900 border-2 border-red-500 rounded"></div> MITRE Technique
                        </div>
                        <div className="flex items-center gap-2 text-sm text-zinc-400">
                            <div className="w-4 h-4 bg-purple-900 border-2 border-purple-500 rounded"></div> Impact / Goal
                        </div>
                    </div>

                    <div className="p-3 bg-blue-950/30 border border-blue-900 rounded-lg">
                        <p className="text-xs text-blue-300">
                            💡 <strong>Tip:</strong> Drag nodes to rearrange. Use controls to zoom and pan.
                        </p>
                    </div>
                </CardContent>
            </Card>

            {/* Right Panel: Graph Visualization */}
            <Card className="bg-zinc-900 border-zinc-800 lg:col-span-2 h-full overflow-hidden">
                <div className="h-full w-full bg-zinc-950">
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onConnect={onConnect}
                        fitView
                        attributionPosition="bottom-left"
                    >
                        <Background color="#27272a" gap={16} />
                        <Controls className="bg-zinc-800 border-zinc-700 fill-zinc-100" />
                    </ReactFlow>
                </div>
            </Card>
        </div>
    );
}
