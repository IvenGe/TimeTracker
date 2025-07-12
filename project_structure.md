# P2P Time Tracking System - Complete Project Structure

## Directory Structure
```
TimeTracker/
├── server/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── timetracking_server.cpp
├── client/
│   ├── p2p_windows_no_openssl.cpp    # Windows client (no SSL)
│   ├── p2p_timetracking_client.cpp   # Cross-platform client (with SSL)
│   └── feedback_functions.cpp         # Helper functions
├── scripts/
│   ├── build_windows.sh               # Cross-compile for Windows
│   ├── build_linux.sh                 # Compile for Linux
│   └── start_tracking.bat             # Windows startup script
└── README.md
```

## File Contents

### 1. server/Dockerfile
```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy source file
COPY timetracking_server.cpp .

# Compile the server
RUN g++ -std=c++11 -pthread timetracking_server.cpp -o timetracking_server -lsqlite3

# Create data directory
RUN mkdir -p /app/data

# Expose ports
EXPOSE 9999 8080

# Run the server
CMD ["./timetracking_server"]
```

### 2. server/docker-compose.yml
```yaml
version: '3.8'

services:
  timetracking:
    build: .
    container_name: timetracking-server
    ports:
      - "9999:9999"   # Relay port
      - "8080:8080"   # Dashboard port
    environment:
      - RELAY_PORT=9999
      - HTTP_PORT=8080
      - DB_PATH=/app/data/timetracking.db
      - ADMIN_PASSWORD=admin123
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

### 3. scripts/build_windows.sh
```bash
#!/bin/bash
# Cross-compile P2P client for Windows from Linux

echo "Building P2P Time Tracking Client for Windows..."

# Check if MinGW is installed
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "MinGW not found! Install with: sudo apt-get install mingw-w64"
    exit 1
fi

# Build 64-bit Windows executable
echo "Compiling 64-bit Windows executable..."
x86_64-w64-mingw32-g++ -std=c++11 -static \
    ../client/p2p_windows_no_openssl.cpp \
    -o ../client/p2p_client_x64.exe \
    -lws2_32 -lwtsapi32 -lpowrprof -ladvapi32 -pthread

if [ $? -eq 0 ]; then
    echo "✓ Successfully built: p2p_client_x64.exe"
else
    echo "✗ Build failed!"
    exit 1
fi

# Build 32-bit Windows executable (optional)
echo "Compiling 32-bit Windows executable..."
i686-w64-mingw32-g++ -std=c++11 -static \
    ../client/p2p_windows_no_openssl.cpp \
    -o ../client/p2p_client_x86.exe \
    -lws2_32 -lwtsapi32 -lpowrprof -ladvapi32 -pthread

if [ $? -eq 0 ]; then
    echo "✓ Successfully built: p2p_client_x86.exe"
else
    echo "✗ 32-bit build failed (optional)"
fi

echo "Build complete!"
```

### 4. scripts/build_linux.sh
```bash
#!/bin/bash
# Compile P2P client for Linux

echo "Building P2P Time Tracking Client for Linux..."

# Check for required libraries
if ! pkg-config --exists openssl; then
    echo "OpenSSL not found! Install with: sudo apt-get install libssl-dev"
    exit 1
fi

# Build Linux executable
echo "Compiling Linux executable..."
g++ -std=c++11 -pthread \
    ../client/p2p_timetracking_client.cpp \
    -o ../client/p2p_client_linux \
    -lcrypto -lssl

if [ $? -eq 0 ]; then
    echo "✓ Successfully built: p2p_client_linux"
    chmod +x ../client/p2p_client_linux
else
    echo "✗ Build failed!"
    exit 1
fi

echo "Build complete!"
```

### 5. scripts/start_tracking.bat
```batch
@echo off
title P2P Time Tracking Client
echo ========================================
echo     P2P Time Tracking Client
echo     Relay Server: 51.178.139.139
echo ========================================
echo.

:: Set default configuration
set RELAY_SERVER=51.178.139.139
set RELAY_PORT=9999
set P2P_PORT=8888

:: Use computer name and username as default device info
set DEVICE_ID=%COMPUTERNAME%
set DEVICE_NAME=%USERNAME%-%COMPUTERNAME%

:: Check if custom config exists
if exist config.txt (
    echo Loading custom configuration...
    for /f "tokens=1,2 delims==" %%a in (config.txt) do set %%a=%%b
)

echo Configuration:
echo   Device ID: %DEVICE_ID%
echo   Device Name: %DEVICE_NAME%
echo   Relay Server: %RELAY_SERVER%:%RELAY_PORT%
echo   P2P Port: %P2P_PORT%
echo.

:: Start the client
p2p_client_x64.exe --relay %RELAY_SERVER% --port %RELAY_PORT% --p2p-port %P2P_PORT% --device "%DEVICE_ID%" --name "%DEVICE_NAME%"

:: Keep window open on exit
echo.
echo Client stopped.
pause
```

### 6. README.md
```markdown
# P2P Time Tracking System

A distributed time tracking system with blockchain-based integrity and peer-to-peer synchronization.

## Architecture

- **Relay Server**: Facilitates peer discovery and stores events (51.178.139.139:9999)
- **Dashboard**: Web interface for monitoring all peers (http://51.178.139.139:8080)
- **P2P Clients**: Track work time and system events, sync with peers

## Features

- Automatic work session tracking
- System event monitoring (lock/unlock, sleep/wake)
- Idle detection with auto-pause
- Blockchain integrity verification
- Offline queue with sync on reconnect
- Real-time dashboard with per-peer statistics

## Quick Start

### Server Setup (Docker)

```bash
cd server
docker-compose up -d
```

### Client Setup (Windows)

1. Download `p2p_client_x64.exe` and `start_tracking.bat`
2. Double-click `start_tracking.bat`
3. Use commands: `start`, `stop`, `status`, `report`

### Client Setup (Linux)

```bash
cd scripts
./build_linux.sh
../client/p2p_client_linux --relay 51.178.139.139 --device MYPC --name "My Computer"
```

## Building from Source

### Cross-compile for Windows (from Linux)

```bash
cd scripts
./build_windows.sh
```

### Compile for Linux

```bash
cd scripts  
./build_linux.sh
```

## Configuration

Create `config.txt` in the same directory as the client:

```
RELAY_SERVER=51.178.139.139
RELAY_PORT=9999
P2P_PORT=8888
DEVICE_ID=CUSTOM_ID
DEVICE_NAME=Custom Name
```

## Commands

- `start` - Start work session
- `stop` - Stop work session  
- `pause` - Pause current session
- `resume` - Resume paused session
- `status` - Show current status
- `report` - Generate work report
- `peers` - List connected peers
- `quit` - Exit application

## System Events Tracked

- Work sessions (start/stop/pause/resume)
- System events (startup/shutdown/sleep/wake)
- Session events (lock/unlock/login/logout)
- Idle detection (configurable threshold)
- Suspicious activity (time jumps, debugger)

## Dashboard Access

View all connected peers and their activity:
http://51.178.139.139:8080

## Security

- SHA256 blockchain hashing
- Tamper detection
- Peer verification
- Encrypted local storage (planned)

## Troubleshooting

### Windows Firewall
Allow the client through Windows Firewall:
- Outbound: 51.178.139.139:9999 (relay)
- Inbound: Your P2P port (default 8888)

### Connection Issues
- Check internet connectivity
- Verify relay server is accessible
- Try different P2P port if 8888 is blocked

### Build Issues
- Windows: Install MinGW-w64
- Linux: Install build-essential, libssl-dev

## License

MIT License - See LICENSE file for details
```

### 7. client/config.txt (example)
```
RELAY_SERVER=51.178.139.139
RELAY_PORT=9999
P2P_PORT=8888
DEVICE_ID=OFFICE_PC
DEVICE_NAME=John's Office Computer
```

## Complete File Listing

### Essential Files:
1. **server/timetracking_server.cpp** - The relay server (from your original post)
2. **client/p2p_windows_no_openssl.cpp** - Windows client with feedback (from artifacts)
3. **client/p2p_timetracking_client.cpp** - Cross-platform client with OpenSSL
4. **server/Dockerfile** - Docker configuration
5. **server/docker-compose.yml** - Docker Compose setup

### Build Scripts:
6. **scripts/build_windows.sh** - Cross-compile for Windows
7. **scripts/build_linux.sh** - Compile for Linux
8. **scripts/start_tracking.bat** - Windows startup script

### Documentation:
9. **README.md** - Complete documentation
10. **client/config.txt** - Example configuration

## Deployment Steps

### 1. Deploy Server (on 51.178.139.139)
```bash
# Clone or copy server files
cd server
docker-compose up -d

# Check logs
docker logs timetracking-server
```

### 2. Build Clients
```bash
# On Linux build machine
cd scripts
chmod +x *.sh
./build_windows.sh
./build_linux.sh
```

### 3. Distribute Clients
- Windows users: `p2p_client_x64.exe` + `start_tracking.bat`
- Linux users: `p2p_client_linux`

### 4. Access Dashboard
- http://51.178.139.139:8080

This structure provides a complete, production-ready P2P time tracking system!