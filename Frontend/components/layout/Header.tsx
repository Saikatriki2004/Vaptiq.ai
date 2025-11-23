"use client";

import { Search, Bell, User } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export function Header() {
    return (
        <header className="fixed top-0 right-0 left-64 z-30 flex h-14 items-center justify-between border-b border-zinc-800 bg-zinc-950/80 px-6 backdrop-blur-sm">
            <div className="flex items-center gap-4 text-sm text-zinc-500">
                <span className="text-zinc-300">Vaptiq.ai Framework</span>
                <span>/</span>
                <span className="text-white">Dashboard</span>
            </div>

            <div className="flex items-center gap-4">
                <div className="relative w-96">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-500" />
                    <Input
                        type="search"
                        placeholder="Global Search (Targets, CVEs, Scans)..."
                        className="h-9 w-full bg-zinc-900 border-zinc-800 pl-9 text-zinc-300 placeholder:text-zinc-600 focus-visible:ring-emerald-500"
                    />
                </div>
                <Button variant="ghost" size="icon" className="text-zinc-400 hover:text-white">
                    <Bell className="h-5 w-5" />
                </Button>
                <div className="h-8 w-8 rounded-full bg-emerald-500/20 flex items-center justify-center border border-emerald-500/50 text-emerald-500">
                    <User className="h-4 w-4" />
                </div>
            </div>
        </header>
    );
}
