#!/bin/bash
# Apply DTB matching fix for Jetson Orin NX (p3767-0001 vs p3767-0000)
# Run with: sudo bash /home/jetson/apply-dtb-fix.sh

set -e
SRC="/home/jetson/dtc.py.fixed"
DST="/opt/nvidia/jetson-io/Utils/dtc.py"
cp "$SRC" "$DST"
echo "Applied fix: $DST"
echo "You can now run: sudo python3 /opt/nvidia/jetson-io/jetson-io.py"
