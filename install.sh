#!/bin/bash

# jsdumper Installation Script for Linux
# This script installs jsdumper as a system-wide binary

set -e

echo "jsdumper Installation Script"
echo "================================"
echo ""

# Check if running as root (needed for /usr/bin installation)
if [ "$EUID" -ne 0 ]; then 
    echo "This script needs root privileges to install to /usr/bin"
    echo "Please run with: sudo ./install.sh"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Installing npm dependencies..."
npm install

echo ""
echo "Creating symlink to /usr/bin/jsdumper..."

# Remove existing symlink if it exists
if [ -L /usr/bin/jsdumper ]; then
    echo "   Removing existing symlink..."
    rm /usr/bin/jsdumper
fi

# Create symlink to the bin script
ln -s "$SCRIPT_DIR/bin/jsdumper" /usr/bin/jsdumper

# Make sure the bin script is executable
chmod +x "$SCRIPT_DIR/bin/jsdumper"

echo ""
echo "Installation complete!"
echo ""
echo "You can now use jsdumper from anywhere:"
echo "  jsdumper <file|directory|->"
echo ""
echo "Example:"
echo "  jsdumper main.js --output ./results"
echo ""
