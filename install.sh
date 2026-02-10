#!/bin/bash

# jsdumper Installation Script for Linux
# This script installs jsdumper as a system-wide binary

set -e

echo "jsdumper Installation Script"
echo "================================"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed"
    echo "Please install Go from https://golang.org/dl/"
    exit 1
fi

# Check if running as root (needed for /usr/bin installation)
if [ "$EUID" -ne 0 ]; then 
    echo "This script needs root privileges to install to /usr/bin"
    echo "Please run with: sudo ./install.sh"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building jsdumper..."
go build -o bin/jsdumper .

if [ ! -f "bin/jsdumper" ]; then
    echo "Error: Build failed"
    exit 1
fi

echo ""
echo "Creating symlink to /usr/bin/jsdumper..."

# Remove existing symlink if it exists
if [ -L /usr/bin/jsdumper ]; then
    echo "   Removing existing symlink..."
    rm /usr/bin/jsdumper
fi

# Create symlink to the binary
ln -s "$SCRIPT_DIR/bin/jsdumper" /usr/bin/jsdumper

# Make sure the binary is executable
chmod +x "$SCRIPT_DIR/bin/jsdumper"

echo ""
echo "Installation complete!"
echo ""
echo "You can now use jsdumper from anywhere:"
echo "  jsdumper <file|directory|->"
echo ""
echo "Examples:"
echo "  jsdumper main.js --output ./results"
echo "  jsdumper -u https://example.com/file.js"
echo "  jsdumper -l urls.txt --output results"
echo ""
