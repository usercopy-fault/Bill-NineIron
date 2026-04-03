#!/bin/bash
# Hook: Auto-generate vulnerability report snippet
TS=$(date +%Y%m%d_%H%M%S)
REPORT="$C2_HOME/reports/vuln_${TS}.md"
mkdir -p "$C2_HOME/reports"

cat > "$REPORT" << EOF
# Vulnerability Finding — $TS

## Event
- **Type:** $C2_EVENT
- **Timestamp:** $C2_TIMESTAMP

## Details
\`\`\`json
$C2_DATA
\`\`\`

## Impact
_TODO: Assess impact_

## Steps to Reproduce
_TODO: Document steps_

## Remediation
_TODO: Suggest fix_
EOF
