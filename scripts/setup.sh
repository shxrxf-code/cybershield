#!/bin/bash
echo "SENTINEL X Setup"
echo "================"
echo "Python: $(python3 --version)"
echo "Node: $(node --version 2>/dev/null || echo missing)"
echo "Rust: $(cargo --version 2>/dev/null || echo missing)"
echo "ClamAV: $(clamscan --version 2>/dev/null | head -1 || echo missing)"
echo "Suricata: $(suricata --version 2>/dev/null | head -1 || echo missing)"
echo ""
echo "Installing Python dependencies..."
pip3 install --break-system-packages -r backend/requirements.txt 2>&1 | tail -3
echo ""
echo "Setup complete. See README.md for usage."
