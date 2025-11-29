'use client'

export default function ConfigErrorPage() {
    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-red-900 via-gray-900 to-black">
            <div className="max-w-md w-full p-8 bg-gray-800/50 backdrop-blur-lg rounded-2xl border border-red-500/30 shadow-2xl">
                <div className="flex flex-col items-center text-center space-y-6">
                    {/* Error Icon */}
                    <div className="w-20 h-20 bg-red-500/20 rounded-full flex items-center justify-center">
                        <svg
                            className="w-12 h-12 text-red-500"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                            />
                        </svg>
                    </div>

                    {/* Title */}
                    <h1 className="text-3xl font-bold text-white">
                        Configuration Error
                    </h1>

                    {/* Description */}
                    <div className="space-y-3 text-gray-300">
                        <p className="text-lg">
                            Authentication is not properly configured.
                        </p>
                        <p className="text-sm text-gray-400">
                            Supabase environment variables are missing or invalid.
                            Please contact your system administrator.
                        </p>
                    </div>

                    {/* Technical Details */}
                    <div className="w-full p-4 bg-black/40 rounded-lg border border-red-500/20">
                        <p className="text-xs font-mono text-red-400">
                            SECURITY: Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY
                        </p>
                    </div>

                    {/* Action */}
                    <div className="pt-4">
                        <p className="text-sm text-gray-400">
                            This application uses fail-closed security.
                            <br />
                            Access is denied when authentication cannot be verified.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    )
}
