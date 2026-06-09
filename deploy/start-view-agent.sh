#!/usr/bin/env bash
# (Re)launch the view-agent if it is not already healthy.
# Idempotent — safe to run from cron: @reboot for boot, */2 * * * * for crash recovery.
#
#   crontab example:
#     @reboot      /opt/view-agent/deploy/start-view-agent.sh
#     */2 * * * *  /opt/view-agent/deploy/start-view-agent.sh
#
# Adjust the three variables to your install. HEALTH_URL must match bind+port in config.json.
AGENT_DIR="/opt/view-agent"
CONFIG="$AGENT_DIR/config.json"
HEALTH_URL="http://127.0.0.1:27200/health"

if curl -s --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
  exit 0                                    # already up -> no-op
fi
pkill -f "cloudflared.*tunnel" 2>/dev/null  # clean orphan tunnels left by a crashed agent
sleep 1
setsid python3 "$AGENT_DIR/view-agent.py" "$CONFIG" > /tmp/view-agent.log 2>&1 < /dev/null &
