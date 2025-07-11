#!/bin/bash

echo "========================================="
echo "Building Portable Windows EXE from Linux"
echo "========================================="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if MinGW is installed
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo -e "${RED}MinGW cross-compiler not found!${NC}"
    echo "Installing MinGW..."
    sudo apt update
    sudo apt install -y mingw-w64
fi

# Compile portable Windows executable
echo "Compiling portable Windows executable..."

# Full static linking for maximum portability
x86_64-w64-mingw32-g++ \
    -std=c++17 \
    -O3 \
    -s \
    -o timetracker-portable.exe \
    timetracker.cpp \
    -lws2_32 \
    -static \
    -static-libgcc \
    -static-libstdc++ \
    -Wl,-Bstatic,--whole-archive \
    -lwinpthread \
    -Wl,--no-whole-archive \
    -DWINVER=0x0501 \
    -D_WIN32_WINNT=0x0501

# Check if compilation succeeded
if [ -f "timetracker-portable.exe" ]; then
    echo
    echo -e "${GREEN}SUCCESS!${NC} Portable executable created: timetracker-portable.exe"
    echo
    echo "File details:"
    ls -lh timetracker-portable.exe
    echo
    echo "This executable will run on any Windows system (XP and newer)"
    echo "No additional DLL files or runtime libraries needed!"
    
    # Optional: Create a ZIP for easy distribution
    if command -v zip &> /dev/null; then
        echo
        echo "Creating distribution package..."
        
        # Create readme
        cat > README.txt << EOF
TimeTracker Portable v1.0
========================

This is a fully portable Windows executable.
No installation required!

Usage:
1. Copy timetracker-portable.exe to any folder
2. Double-click to run
3. Press Ctrl+C to stop and save work session

Configuration:
- Edit timetracker.conf (created on first run)
- Logs saved to work_hours.log

Requirements:
- Windows XP or newer
- No additional files needed!

EOF
        
        # Create sample config
        cat > timetracker.conf << EOF
project_name=My Project
employee_name=Your Name
auto_submit=0
submit_email=admin@company.com
update_interval=60
EOF
        
        # Create ZIP
        zip -q timetracker-portable.zip timetracker-portable.exe README.txt timetracker.conf
        rm README.txt
        
        echo -e "${GREEN}Created distribution package:${NC} timetracker-portable.zip"
        ls -lh timetracker-portable.zip
    fi
    
else
    echo
    echo -e "${RED}BUILD FAILED!${NC}"
    echo "Check the error messages above."
    exit 1
fi

echo
echo "Done!"
