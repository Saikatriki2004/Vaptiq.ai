import { Card, CardContent } from "@/components/ui/card";
import { ShieldAlert, Target, Activity, AlertTriangle } from "lucide-react";

const kpiData = [
    {
        title: "Total Findings",
        value: "127",
        icon: ShieldAlert,
        color: "text-white",
        subtext: "+12 from last scan",
    },
    {
        title: "Critical Risk",
        value: "3",
        icon: AlertTriangle,
        color: "text-red-500",
        subtext: "Immediate action required",
    },
    {
        title: "High Risk",
        value: "14",
        icon: Activity,
        color: "text-orange-500",
        subtext: "Patch within 24h",
    },
    {
        title: "Active Target",
        value: "api.stripe.com",
        icon: Target,
        color: "text-emerald-500",
        subtext: "Scanning in progress...",
        isMono: true,
    },
];

export function KPICards() {
    return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {kpiData.map((item) => (
                <Card key={item.title} className="bg-zinc-900 border-zinc-800">
                    <CardContent className="p-6 flex flex-col justify-between h-full">
                        <div className="flex items-center justify-between space-y-0 pb-2">
                            <p className="text-sm font-medium text-zinc-400">{item.title}</p>
                            <item.icon className={`h-4 w-4 ${item.color}`} />
                        </div>
                        <div>
                            <div className={`text-2xl font-bold ${item.color} ${item.isMono ? "font-mono text-lg truncate" : ""}`}>
                                {item.value}
                            </div>
                            <p className="text-xs text-zinc-500 mt-1">{item.subtext}</p>
                        </div>
                    </CardContent>
                </Card>
            ))}
        </div>
    );
}
