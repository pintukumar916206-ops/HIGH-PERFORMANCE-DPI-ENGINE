set -e

echo "starting analyzer..."

export METRICS_FILE="/app/metrics.json"
export CONFIG_FILE="${CONFIG_FILE:-/app/rules.json}"
export PCAP_FILE="${PCAP_FILE:-/app/test_dpi.pcap}"

if [ -f "$PCAP_FILE" ]; then
    echo "input: $PCAP_FILE"
    /app/traffic_engine --input "$PCAP_FILE" --rules "$CONFIG_FILE" 2>&1 &
    ENGINE_PID=$!
    sleep 2
else
    echo "warn: input file missing at $PCAP_FILE"
fi

echo "starting dashboard..."
exec python3 -m scripts.dashboard
