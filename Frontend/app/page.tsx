export default function HomePage() {
    return (
        <main className="flex min-h-screen flex-col items-center justify-center bg-slate-950 text-emerald-500">
            <h1 className="text-6xl font-bold mb-4 text-emerald-300">Vaptiq.ai</h1>
            <p className="text-xl mb-8">Agentic VAPT SaaS Platform</p>
            <a
                href="/dashboard"
                className="px-6 py-3 bg-emerald-600 hover:bg-emerald-700 text-white rounded-md transition-colors"
            >
                Go to Dashboard
            </a>
        </main>
    );
}
