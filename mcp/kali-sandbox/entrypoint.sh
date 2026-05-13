#!/bin/bash
set -e

echo "[*] Starting RedAmon MCP container..."

# Tunnel manager API first (instant, runs in background).
# Allows the webapp to push tunnel config at any time during boot.
python3 /opt/mcp_servers/tunnel_manager.py &

# Wait for tunnel manager to bind to port 8015
for i in $(seq 1 10); do
    curl -sf http://localhost:8015/health > /dev/null 2>&1 && break
    [ "$i" -eq 10 ] && echo "[!] Tunnel manager failed to start on port 8015"
    sleep 1
done
echo "[*] Tunnel manager ready on port 8015"

# Initialize Metasploit database synchronously: it's fast (~10-30s) and
# required before any msf tool call works, so we don't want a race window.
echo "[*] Initializing Metasploit database..."
msfdb init 2>/dev/null || true

# Slow updates and tunnel config fetch run in the background so the MCP
# servers can bind their ports immediately and the docker healthcheck passes.
deferred_init() {
    if [ "${MSF_AUTO_UPDATE:-true}" = "true" ]; then
        echo "[*] [deferred] Updating Metasploit modules..."
        MSF_OUT=$(msfconsole -q -x "msfupdate; exit" 2>&1 || true)
        if echo "$MSF_OUT" | grep -q "no longer supported"; then
            echo "[*] [deferred] msfupdate deprecated on this base image; skipping (refresh manually via 'apt install metasploit-framework' on the host image)"
        elif echo "$MSF_OUT" | grep -qiE "error|failed"; then
            echo "[!] [deferred] msfupdate reported issues; trying apt fallback..."
            (apt-get update -qq && apt-get install -y -qq metasploit-framework) >/dev/null 2>&1 \
                && echo "[*] [deferred] Metasploit update complete (via apt)" \
                || echo "[!] [deferred] apt fallback failed, continuing with existing modules"
        else
            echo "[*] [deferred] Metasploit update complete"
        fi
    else
        echo "[*] [deferred] Skipping Metasploit update (MSF_AUTO_UPDATE=false)"
    fi

    if [ "${NUCLEI_AUTO_UPDATE:-true}" = "true" ]; then
        echo "[*] [deferred] Updating nuclei templates..."
        nuclei -update-templates 2>/dev/null || echo "[!] Nuclei template update failed"
    fi

    WEBAPP_URL="${WEBAPP_API_URL:-http://webapp:3000}"
    echo "[*] [deferred] Fetching tunnel config from webapp..."
    TUNNEL_CONFIG=""
    for i in $(seq 1 30); do
        TUNNEL_CONFIG=$(curl -sf "${WEBAPP_URL}/api/global/tunnel-config" 2>/dev/null) && break
        echo "[*] [deferred] Waiting for webapp... (attempt $i/30)"
        sleep 2
    done

    if [ -n "$TUNNEL_CONFIG" ] && [ "$TUNNEL_CONFIG" != '{}' ] && [ "$TUNNEL_CONFIG" != '{"ngrokAuthtoken":"","chiselServerUrl":"","chiselAuth":""}' ]; then
        echo "[*] [deferred] Applying tunnel config from database..."
        PUSH_OK=false
        for j in $(seq 1 3); do
            if curl -sf -X POST http://localhost:8015/tunnel/configure \
                -H 'Content-Type: application/json' \
                -d "$TUNNEL_CONFIG" > /dev/null 2>&1; then
                PUSH_OK=true
                break
            fi
            echo "[!] [deferred] Tunnel config push failed (attempt $j/3), retrying..."
            sleep 2
        done
        if [ "$PUSH_OK" = "false" ]; then
            echo "[!] [deferred] Failed to apply tunnel config after 3 attempts; tunnels will not start automatically"
            echo "[!] [deferred] Configure tunnels in Global Settings > Tunneling (changes push immediately)"
        fi
    else
        echo "[*] [deferred] No tunnel credentials configured (set them in Global Settings > Tunneling)"
    fi

    echo "[*] [deferred] Initialization complete"
}

deferred_init &

echo "[*] Starting terminal WebSocket server..."
python3 /opt/mcp_servers/terminal_server.py &

echo "[*] Starting MCP servers..."
exec python3 run_servers.py "$@"
