"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { CheckCircle2, Copy, Lock, ShieldAlert, RefreshCw, AlertTriangle } from "lucide-react";

interface TargetVerificationProps {
    targetId: string;
    domain: string;
    verificationToken: string;
    onVerified: () => void;
    backendUrl?: string;
}

export function TargetVerification({
    targetId,
    domain,
    verificationToken,
    onVerified,
    backendUrl = "http://localhost:8000"
}: TargetVerificationProps) {
    const [isVerifying, setIsVerifying] = useState(false);
    const [status, setStatus] = useState<"PENDING" | "SUCCESS" | "FAILED">("PENDING");
    const [errorMessage, setErrorMessage] = useState("");
    const [copySuccess, setCopySuccess] = useState(false);

    const copyToClipboard = async () => {
        try {
            await navigator.clipboard.writeText(verificationToken);
            setCopySuccess(true);
            setTimeout(() => setCopySuccess(false), 2000);
        } catch (err) {
            console.error("Failed to copy:", err);
        }
    };

    const handleVerifyCheck = async () => {
        setIsVerifying(true);
        setErrorMessage("");

        try {
            const response = await fetch(`${backendUrl}/targets/${targetId}/verify`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
            });

            const result = await response.json();

            if (result.success && result.is_verified) {
                setStatus("SUCCESS");
                onVerified();
            } else {
                setStatus("FAILED");
                setErrorMessage(result.message || "Verification failed. Please check your DNS records.");
            }
        } catch (error) {
            setStatus("FAILED");
            setErrorMessage("Failed to connect to verification service. Please ensure the backend is running.");
            console.error("Verification error:", error);
        } finally {
            setIsVerifying(false);
        }
    };

    if (status === "SUCCESS") {
        return (
            <Alert className="bg-emerald-950/50 border-emerald-600 text-emerald-400">
                <CheckCircle2 className="h-4 w-4" />
                <AlertTitle className="font-semibold">✓ Ownership Verified</AlertTitle>
                <AlertDescription>
                    Domain ownership confirmed for <strong className="text-emerald-300">{domain}</strong>.
                    You are now authorized to scan this target.
                </AlertDescription>
            </Alert>
        );
    }

    return (
        <Card className="w-full border-orange-800/50 bg-slate-950/90 backdrop-blur">
            <CardHeader>
                <div className="flex items-center gap-2 text-orange-500">
                    <ShieldAlert className="h-5 w-5" />
                    <CardTitle className="text-xl">Domain Ownership Verification Required</CardTitle>
                </div>
                <CardDescription className="text-slate-400 mt-2">
                    To prevent unauthorized scanning, you must prove you own <strong className="text-slate-200">{domain}</strong> by adding a DNS TXT record.
                </CardDescription>
            </CardHeader>

            <CardContent className="space-y-5">
                {/* Step 1: Instructions */}
                <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-300 uppercase tracking-wide flex items-center gap-2">
                        <span className="flex items-center justify-center w-5 h-5 rounded-full bg-orange-600 text-white text-xs">1</span>
                        Add DNS TXT Record
                    </label>
                    <div className="relative">
                        <div className="flex items-center gap-2 p-3 rounded-md bg-slate-900/80 border border-slate-800 hover:border-orange-800/50 transition-colors">
                            <code className="text-sm text-orange-300 flex-grow font-mono break-all select-all">
                                {verificationToken}
                            </code>
                            <Button
                                variant="ghost"
                                size="icon"
                                onClick={copyToClipboard}
                                className="hover:text-orange-400 hover:bg-slate-800 flex-shrink-0"
                                title="Copy to clipboard"
                            >
                                {copySuccess ? (
                                    <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                                ) : (
                                    <Copy className="h-4 w-4" />
                                )}
                            </Button>
                        </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-800 rounded-md p-3 space-y-1">
                        <p className="text-xs text-slate-400 leading-relaxed">
                            <strong className="text-slate-300">Instructions:</strong>
                        </p>
                        <ol className="text-xs text-slate-400 space-y-1 ml-4 list-decimal">
                            <li>Log in to your DNS provider (GoDaddy, Cloudflare, AWS Route53, Namecheap, etc.)</li>
                            <li>Navigate to DNS management for <span className="text-orange-400 font-mono">{domain}</span></li>
                            <li>Add a new <strong>TXT record</strong> with the value shown above</li>
                            <li>Set the hostname to <span className="text-orange-400 font-mono">@</span> (root domain)</li>
                            <li>Save the record and wait 1-5 minutes for DNS propagation</li>
                        </ol>
                    </div>
                </div>

                {/* Step 2: Verify Button */}
                <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-300 uppercase tracking-wide flex items-center gap-2">
                        <span className="flex items-center justify-center w-5 h-5 rounded-full bg-orange-600 text-white text-xs">2</span>
                        Verify Ownership
                    </label>
                    <p className="text-xs text-slate-500">
                        After adding the TXT record, click the button below to verify domain ownership.
                    </p>
                </div>
            </CardContent>

            <CardFooter className="flex flex-col items-start gap-3 pt-2">
                {status === "FAILED" && (
                    <Alert variant="destructive" className="bg-red-950/50 border-red-900 text-red-200 w-full">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription className="text-sm">{errorMessage}</AlertDescription>
                    </Alert>
                )}

                <Button
                    onClick={handleVerifyCheck}
                    disabled={isVerifying}
                    className="w-full bg-orange-600 hover:bg-orange-700 text-white font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {isVerifying ? (
                        <>
                            <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                            Checking DNS Records...
                        </>
                    ) : (
                        <>
                            <Lock className="mr-2 h-4 w-4" />
                            Verify Domain Ownership
                        </>
                    )}
                </Button>

                <p className="text-xs text-slate-500 text-center w-full">
                    DNS propagation typically takes 1-5 minutes. If verification fails, please wait a moment and try again.
                </p>
            </CardFooter>
        </Card>
    );
}
