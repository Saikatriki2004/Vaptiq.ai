"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
    LayoutDashboard,
    Radar,
    Network,
    BarChart3,
    FileText,
    Settings,
    ShieldCheck,
    Clock,
} from "lucide-react";

const navItems = [
    {
        title: "Dashboard",
        href: "/dashboard",
        icon: LayoutDashboard,
    },
    {
        title: "History",
        href: "/dashboard/history",
        icon: Clock,
    },
    {
        title: "Attack Paths",
        href: "/dashboard/attack-paths",
        icon: Network,
    },
    {
        title: "Analytics",
        href: "/dashboard/analytics",
        icon: BarChart3,
    },
    {
        title: "Reports",
        href: "/dashboard/reports",
        icon: FileText,
    },
    {
        title: "Settings",
        href: "/dashboard/settings",
        icon: Settings,
    },
];

export function Sidebar() {
    const pathname = usePathname();

    return (
        <div className="fixed left-0 top-0 z-40 h-screen w-64 border-r border-zinc-800 bg-zinc-900 text-zinc-400">
            <div className="flex h-14 items-center border-b border-zinc-800 px-6">
                <Link href="/dashboard" className="flex items-center gap-2 font-bold text-white">
                    <ShieldCheck className="h-6 w-6 text-emerald-500" />
                    <span>VAPTIQ</span>
                    <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                </Link>
            </div>
            <nav className="flex flex-col gap-1 p-4">
                {navItems.map((item) => {
                    const isActive = pathname === item.href;
                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            className={cn(
                                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors hover:bg-zinc-800 hover:text-white",
                                isActive &&
                                "bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 hover:text-emerald-400 border-l-2 border-emerald-500 rounded-l-none"
                            )}
                        >
                            <item.icon className="h-4 w-4" />
                            {item.title}
                        </Link>
                    );
                })}
            </nav>
            <div className="absolute bottom-4 left-0 w-full px-4">
                <div className="rounded-md bg-zinc-950 p-4 border border-zinc-800">
                    <p className="text-xs font-medium text-zinc-500 uppercase mb-2">System Status</p>
                    <div className="flex items-center gap-2 text-sm text-emerald-500">
                        <div className="h-2 w-2 rounded-full bg-emerald-500" />
                        Operational
                    </div>
                </div>
            </div>
        </div>
    );
}
