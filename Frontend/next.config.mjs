/** @type {import('next').NextConfig} */
const nextConfig = {   webpack: (config, { isServer }) => {
        // Suppress webpack cache warnings on Windows (drive letter case mismatch)
        config.infrastructureLogging = {
            level: 'error', // Only show errors, suppress warnings
        };
        return config;
    },
};

export default nextConfig;
