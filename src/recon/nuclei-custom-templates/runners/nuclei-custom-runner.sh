#!/bin/bash
# Custom Nuclei Runner for 2026 Templates
# Usage: ./nuclei-custom-runner.sh <target> [output-file]

TARGET="${1:-localhost:8080}"
OUTPUT="${2:-results.txt}"
TEMPLATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../templates" && pwd)"

echo "🎯 Custom Nuclei Runner - 2026 Templates"
echo "=========================================="
echo "Target: $TARGET"
echo "Templates: $TEMPLATES_DIR"
echo "Output: $OUTPUT"
echo ""

# Run templates by category
echo "[*] Running Supply Chain templates..."
nuclei -t "$TEMPLATES_DIR/supply-chain-*.yaml" -u "$TARGET" -o "$OUTPUT.supply-chain" 2>/dev/null

echo "[*] Running API Exploitation templates..."
nuclei -t "$TEMPLATES_DIR/api-*.yaml" -u "$TARGET" -o "$OUTPUT.api" 2>/dev/null

echo "[*] Running Authentication Bypass templates..."
nuclei -t "$TEMPLATES_DIR/auth-*.yaml" -u "$TARGET" -o "$OUTPUT.auth" 2>/dev/null

echo "[*] Running Data Exfiltration templates..."
nuclei -t "$TEMPLATES_DIR/exfil-*.yaml" -u "$TARGET" -o "$OUTPUT.exfil" 2>/dev/null

echo "[*] Running Infrastructure templates..."
nuclei -t "$TEMPLATES_DIR/infra-*.yaml" -u "$TARGET" -o "$OUTPUT.infra" 2>/dev/null

echo "[*] Running Logic Flaw templates..."
nuclei -t "$TEMPLATES_DIR/logic-*.yaml" -u "$TARGET" -o "$OUTPUT.logic" 2>/dev/null

# Aggregate results
echo ""
echo "[+] Aggregating results..."
cat "$OUTPUT".* > "$OUTPUT" 2>/dev/null
rm -f "$OUTPUT".* 2>/dev/null

echo "[+] Scan complete!"
echo "[+] Results saved to: $OUTPUT"
echo ""
echo "Summary:"
grep -c "severity" "$OUTPUT" | xargs echo "Total vulnerabilities found:"
