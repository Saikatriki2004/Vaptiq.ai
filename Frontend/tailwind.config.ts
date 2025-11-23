import type { Config } from "tailwindcss";

const config = {
    darkMode: ["class"],
    content: [
        './pages/**/*.{ts,tsx}',
        './components/**/*.{ts,tsx}',
        './app/**/*.{ts,tsx}',
        './src/**/*.{ts,tsx}',
    ],
    prefix: "",
    theme: {
        container: {
            center: true,
            padding: "2rem",
            screens: {
                "2xl": "1400px",
            },
        },
        extend: {
            colors: {
                border: "hsl(var(--border))",
                input: "hsl(var(--input))",
                ring: "hsl(var(--ring))",
                background: "#020617", // slate-950
                foreground: "#f8fafc", // slate-50
                primary: {
                    DEFAULT: "#10b981", // emerald-500
                    foreground: "#020617",
                },
                secondary: {
                    DEFAULT: "#1e293b", // slate-800
                    foreground: "#f8fafc",
                },
                destructive: {
                    DEFAULT: "hsl(var(--destructive))",
                    foreground: "hsl(var(--destructive-foreground))",
                },
                muted: {
                    DEFAULT: "#334155", // slate-700
                    foreground: "#94a3b8", // slate-400
                },
                accent: {
                    DEFAULT: "#10b981",
                    foreground: "#020617",
                },
                popover: {
                    DEFAULT: "#0f172a", // slate-900
                    foreground: "#f8fafc",
                },
                card: {
                    DEFAULT: "#0f172a", // slate-900
                    foreground: "#f8fafc",
                },
            },
            borderRadius: {
                lg: "var(--radius)",
                md: "calc(var(--radius) - 2px)",
                sm: "calc(var(--radius) - 4px)",
            },
            keyframes: {
                "accordion-down": {
                    from: { height: "0" },
                    to: { height: "var(--radix-accordion-content-height)" },
                },
                "accordion-up": {
                    from: { height: "var(--radix-accordion-content-height)" },
                    to: { height: "0" },
                },
            },
            animation: {
                "accordion-down": "accordion-down 0.2s ease-out",
                "accordion-up": "accordion-up 0.2s ease-out",
            },
        },
    },
    plugins: [require("tailwindcss-animate")],
} satisfies Config;

export default config;
