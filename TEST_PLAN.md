# Vaptiq.ai Test Plan

This document outlines the core workflows and test scenarios for the Vaptiq.ai application. It is intended to guide AI-driven testing tools like TestSprite in generating comprehensive test coverage.

## Application Overview
Vaptiq.ai is an Agentic VAPT (Vulnerability Assessment and Penetration Testing) SaaS platform. It allows users to scan domains for vulnerabilities, visualize attack paths, and generate reports.

## Core Workflows

### 1. Authentication
- **Login**: Users should be able to log in with valid credentials.
  - **Path**: `/login`
  - **Success**: Redirects to `/dashboard`.
  - **Failure**: Shows error message for invalid credentials.
- **Protected Routes**: Unauthenticated users accessing `/dashboard` should be redirected to `/login`.

### 2. Dashboard & Scanning
- **Dashboard Load**: The dashboard should load successfully and display the scan interface.
  - **Path**: `/dashboard`
- **Start Scan**: Users can enter a target domain (e.g., `example.com`) and start a scan.
  - **Action**: Input domain, click "Start Scan".
  - **Expected**: Scan logs appear in the terminal window. Status updates to "Scanning".
- **Scan Visualization**: Vulnerability charts and statistics should update as the scan progresses.

### 3. Attack Path Simulation
- **View Attack Paths**: Users can visualize potential attack vectors.
  - **Path**: `/dashboard/attack-paths`
- **Graph Interaction**: The node graph should be interactive (zoom, pan).
- **Simulation**: Clicking "Simulate Attack" should trigger a simulation and update the graph.

### 4. Scan History
- **View History**: Users can view a list of past scans.
  - **Path**: `/dashboard/history`
- **Filter/Sort**: Users should be able to filter scans by date or status.

### 5. Reporting
- **Generate Report**: Users can generate PDF reports for completed scans.
  - **Path**: `/dashboard/reports`
  - **Action**: Select a scan, click "Generate Report".
  - **Expected**: PDF file is downloaded.
- **Report Content**: The report should contain a summary of vulnerabilities and remediation steps.

## Technical Details
- **Frontend**: Next.js 14, Tailwind CSS, Shadcn UI.
- **Backend**: FastAPI, Redis, Celery.
- **Testing Framework**: Playwright.
- **Base URL**: `http://localhost:3000` (Frontend), `http://localhost:8000` (Backend).
