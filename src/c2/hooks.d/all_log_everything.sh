#!/bin/bash
# Hook: Log every event to a structured log file
echo "[$(date -Iseconds)] [$C2_EVENT] $C2_DATA" >> "$C2_HOME/logs/all_events.log"
