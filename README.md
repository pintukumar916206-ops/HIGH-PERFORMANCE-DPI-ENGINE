# Network Traffic Analysis Engine

A high-performance C++ packet processing engine with a unified real-time monitoring dashboard. Designed for protocol identification (DPI), SNI extraction, and anomaly detection.

## Quick Start (Local)

The project includes a unified cross-platform setup script.

1. **Setup Environment**:
   ```bash
   python setup.py
   ```
   This will install Python dependencies, set up your .env file, and attempt to build the C++ engine.

2. **Run Dashboard**:
   ```bash
   python scripts/dashboard.py
   ```
   Access the UI at http://localhost:5000. Use credentials from .env.

3. **Run in Terminal**:
   You can run the analysis engine directly in your terminal with real-time updates:
   ```bash
   .\mock_engine.exe --url google.com --stats --interval 3
   ```

## Production Deployment (Docker)

Deployment files are located in the deploy/ directory.

1. **Build and Launch**:
   ```bash
   cd deploy
   docker compose up -d --build
   ```

2. **Services**:
   - **Unified Dashboard**: http://localhost:5000
   - **Metrics Data**: http://localhost:9090

## Project Structure

- src/, include/: C++ Engine source and headers.
- scripts/: Unified dashboard and utility scripts.
- configs/: Centralized configuration (rules.json, etc.).
- deploy/: Docker and production deployment manifests.
- backups/: Legacy scripts and original setup files.

## Security and Performance

- **Unified Logic**: URL analysis and live capture are combined into a single application.
- **Role-Based Access**: Dashboard is secured via session-based authentication.
- **High Throughput**: 1.9 Mpps throughput on standard hardware.
- **Safe Parsing**: Zero-copy header inspection with strict boundary checks.

## Development

### Prerequisites
- Python 3.8+
- CMake >= 3.16
- GCC/MinGW (C++14+)
- libpcap development files

### Local Build
```bash
mkdir build && cd build
cmake ..
cmake --build .
```
