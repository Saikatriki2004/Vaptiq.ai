# Backend/Dockerfile

# Use Python 3.11 (Debian-based for easy tool installation)
FROM python:3.11-slim

# 1. Install System Security Tools (The "Muscle")
# We install Nmap, Nikto, SQLMap, and other utilities
RUN apt-get update && apt-get install -y \
    nmap \
    netcat-openbsd \
    nikto \
    sqlmap \
    dnsutils \
    whois \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# 2. Setup Work Directory
WORKDIR /app

# 3. Install Python Dependencies
# Copy requirements first to leverage Docker cache (path relative to root)
COPY Backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy Schema & Generate Client
COPY packages/database/schema.prisma ./prisma/schema.prisma
RUN prisma generate --schema=./prisma/schema.prisma

# 5. Copy Backend Source Code (path relative to root)
COPY Backend/ .

# 6. Run the API
# Expose port 8000 for the frontend/host to connect
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
