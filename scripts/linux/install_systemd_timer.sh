#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYSTEMD_DIR="${SYSTEMD_DIR:-$HOME/.config/systemd/user}"
RUN_USER="${RUN_USER:-$USER}"

mkdir -p "$SYSTEMD_DIR"

cat >"$SYSTEMD_DIR/gha-cascade-collect.service" <<EOF
[Unit]
Description=GHA Cascade Analyzer collection job
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$ROOT_DIR
ExecStart=$ROOT_DIR/scripts/linux/run_collection.sh
User=$RUN_USER
EOF

cat >"$SYSTEMD_DIR/gha-cascade-collect.timer" <<EOF
[Unit]
Description=Run GHA Cascade Analyzer collection every 6 hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
Persistent=true
Unit=gha-cascade-collect.service

[Install]
WantedBy=timers.target
EOF

cat >"$SYSTEMD_DIR/gha-cascade-analyze.service" <<EOF
[Unit]
Description=GHA Cascade Analyzer daily analysis job
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$ROOT_DIR
ExecStart=$ROOT_DIR/scripts/linux/run_analysis.sh
User=$RUN_USER
EOF

cat >"$SYSTEMD_DIR/gha-cascade-analyze.timer" <<EOF
[Unit]
Description=Run GHA Cascade Analyzer analysis daily

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
Unit=gha-cascade-analyze.service

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now gha-cascade-collect.timer
systemctl --user enable --now gha-cascade-analyze.timer

echo "Installed systemd user timers into $SYSTEMD_DIR"
echo "Check status with:"
echo "  systemctl --user list-timers | grep gha-cascade"
