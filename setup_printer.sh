#!/bin/bash
# Printer setup script for Jetson/Ubuntu
# Run this with: sudo bash setup_printer.sh

set -e

echo "=== Setting up printing on this machine ==="

# Update package list
echo "Updating package lists..."
apt-get update -qq

# Install CUPS and related tools
echo "Installing CUPS printing system..."
apt-get install -y cups cups-client cups-bsd system-config-printer printer-driver-all

# Start and enable CUPS service
echo "Starting CUPS service..."
systemctl start cups || service cups start || echo "Could not start via systemctl/service, check manually"
systemctl enable cups || true

# Allow admin access (for web interface)
echo "Configuring CUPS for admin access..."
cupsenable -a || true
cupsctl --share-printers || true

# Create a default PDF printer for testing (virtual printer that outputs PDF)
echo "Setting up a virtual PDF printer for testing..."
lpadmin -p PDF_Printer -E -v file:/var/spool/cups-pdf/%s.pdf -m everywhere || echo "PDF printer setup may need GUI adjustment"

# Restart CUPS
echo "Restarting CUPS..."
systemctl restart cups || service cups restart || true

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "To test printing:"
echo "1. echo 'Hello from Jetson Printer!' | lp -d PDF_Printer"
echo "2. Or use the web interface: http://localhost:631"
echo "3. For GUI: system-config-printer"
echo ""
echo "If you have a physical printer:"
echo "- Connect it via USB or network"
echo "- Run: system-config-printer to add it"
echo "- Or access CUPS web UI at http://localhost:631"
echo ""
echo "Check status with: lpstat -t"
echo "List printers: lpstat -p"
echo ""
echo "Note: If systemctl fails, this Jetson may use a different service manager. Check with 'ps aux | grep cupsd'"
