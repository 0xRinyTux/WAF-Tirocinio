#!/bin/sh

chown nobody -R /execute/

# Create socket directory if SOCKET_DIR is set
if [ -n "$SOCKET_DIR" ]; then
    mkdir -p "$SOCKET_DIR"
    chown nobody:nobody "$SOCKET_DIR"
    chmod 755 "$SOCKET_DIR"
fi

# Resolve SIMULATION_TARGET to SIMULATION_IP if set
if [ -n "$SIMULATION_TARGET" ]; then
    echo "[*] Resolving SIMULATION_TARGET: $SIMULATION_TARGET"
    RESOLVED_IP=""
    for i in 1 2 3 4 5; do
        RESOLVED_IP=$(python3 -c "import socket; 
try: 
    print(socket.gethostbyname('$SIMULATION_TARGET'))
except: 
    pass")
        if [ -n "$RESOLVED_IP" ]; then
            break
        fi
        echo "[.] Waiting for DNS resolution... ($i/5)"
        sleep 2
    done

    if [ -n "$RESOLVED_IP" ]; then
        export SIMULATION_IP="$RESOLVED_IP"
        echo "[+] SIMULATION_IP set to: $SIMULATION_IP"
    else
        echo "[!] Failed to resolve SIMULATION_TARGET after attempts"
    fi
fi

echo "[*] Attempting to start with capabilities..."

if capsh --caps="cap_net_admin,cap_net_raw,cap_setpcap,cap_setuid,cap_setgid,cap_sys_nice+eip" \
    --keep=1 \
    --user=nobody \
    --addamb=cap_net_admin,cap_net_raw,cap_sys_nice \
    -- -c "exit 0"
then
  exec capsh --caps="cap_net_admin,cap_net_raw,cap_setpcap,cap_setuid,cap_setgid,cap_sys_nice+eip" \
    --keep=1 \
    --user=nobody \
    --addamb=cap_net_admin,cap_net_raw,cap_sys_nice \
    -- -c "python3 /execute/app.py DOCKER"
else
    echo "[!] capsh failed, running with root user"
    exec python3 /execute/app.py DOCKER
fi

