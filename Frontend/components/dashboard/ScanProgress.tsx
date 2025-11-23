import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Terminal } from "lucide-react";

export function ScanProgress() {
    return (
        <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400 flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-emerald-500" />
                    Active Agent Status
                </CardTitle>
            </CardHeader>
            <CardContent>
                <div className="space-y-4">
                    <div className="flex justify-between text-sm">
                        <span className="text-white">Phase 3/5: Verifying SQL Injection Vectors</span>
                        <span className="text-emerald-500 font-mono">60%</span>
                    </div>
                    <Progress value={60} className="h-2 bg-zinc-800" indicatorClassName="bg-emerald-500" />
                    <div className="grid grid-cols-3 gap-2 pt-2">
                        <div className="text-xs text-zinc-500">
                            <span className="block text-zinc-400 mb-1">Target</span>
                            <span className="font-mono">192.168.1.105</span>
                        </div>
                        <div className="text-xs text-zinc-500">
                            <span className="block text-zinc-400 mb-1">Duration</span>
                            <span className="font-mono">00:14:23</span>
                        </div>
                        <div className="text-xs text-zinc-500">
                            <span className="block text-zinc-400 mb-1">Requests</span>
                            <span className="font-mono">14,203</span>
                        </div>
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
