"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";

const data = [
    { name: "Critical", value: 3, color: "#ef4444" }, // Red-500
    { name: "High", value: 14, color: "#f97316" },   // Orange-500
    { name: "Medium", value: 45, color: "#eab308" }, // Yellow-500
    { name: "Low", value: 65, color: "#3b82f6" },    // Blue-500
];

export function VulnChart() {
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
    }, []);

    if (!mounted) return null;

    return (
        <Card className="bg-zinc-900 border-zinc-800 h-full">
            <CardHeader className="pb-0">
                <CardTitle className="text-sm font-medium text-zinc-400">
                    Vulnerability Distribution
                </CardTitle>
            </CardHeader>
            <CardContent className="h-[250px]">
                <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                        <Pie
                            data={data}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                            stroke="none"
                        >
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                        </Pie>
                        <Tooltip
                            contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '8px' }}
                            itemStyle={{ color: '#e4e4e7' }}
                        />
                        <Legend
                            verticalAlign="middle"
                            align="right"
                            layout="vertical"
                            iconType="circle"
                            formatter={(value: string, entry: any) => (
                                <span className="text-zinc-400 text-sm ml-2">{value}</span>
                            )}
                        />
                    </PieChart>
                </ResponsiveContainer>
            </CardContent>
        </Card>
    );
}
