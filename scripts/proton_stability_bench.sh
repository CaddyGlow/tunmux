#!/usr/bin/env bash
set -euo pipefail

BIN="${TUNMUX_BIN:-target/release/tunmux}"
COUNTRY=""
COUNT=5
SAMPLES=6
SAMPLE_SECS=10
URL="https://speedtest.milkywan.fr/files/10G.iso"
SERVERS_CSV=""
CONNECT_BEST=0
RESTORE_ORIGINAL=1
P2P=0

usage() {
  cat <<'EOF'
Usage: scripts/proton_stability_bench.sh [options]

Benchmark Proton local-proxy stability by cycling servers and measuring:
- Download throughput (curl speed_download)
- TTFB jitter (time_starttransfer stddev)

Options:
  --country CC         Filter server list by country code (e.g. FR, US)
  --count N            Number of candidate servers to test from list (default: 5)
  --servers CSV        Explicit comma-separated servers (e.g. FR#16,FR#8,FR#20)
  --samples N          Samples per server (default: 6)
  --sample-secs N      Seconds per sample (default: 10)
  --url URL            Download URL (default: speedtest.milkywan.fr 10G.iso)
  --p2p                Use --p2p when listing servers
  --connect-best       Connect best-ranked server at end
  --no-restore         Do not restore originally connected Proton server
  -h, --help           Show this help

Notes:
- Requires a logged-in Proton session in tunmux.
- Disconnects Proton connections during the benchmark.
- Non-Proton connections (AirVPN/Mullvad/IVPN) are left untouched.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --country) COUNTRY="${2:-}"; shift 2 ;;
    --count) COUNT="${2:-}"; shift 2 ;;
    --samples) SAMPLES="${2:-}"; shift 2 ;;
    --sample-secs) SAMPLE_SECS="${2:-}"; shift 2 ;;
    --url) URL="${2:-}"; shift 2 ;;
    --servers) SERVERS_CSV="${2:-}"; shift 2 ;;
    --connect-best) CONNECT_BEST=1; shift ;;
    --no-restore) RESTORE_ORIGINAL=0; shift ;;
    --p2p) P2P=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -x "$BIN" ]]; then
  echo "Binary not found/executable: $BIN" >&2
  echo "Build first: cargo build --release -p tunmux" >&2
  exit 1
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || (( COUNT < 1 )); then
  echo "--count must be >= 1" >&2
  exit 2
fi
if ! [[ "$SAMPLES" =~ ^[0-9]+$ ]] || (( SAMPLES < 1 )); then
  echo "--samples must be >= 1" >&2
  exit 2
fi
if ! [[ "$SAMPLE_SECS" =~ ^[0-9]+$ ]] || (( SAMPLE_SECS < 2 )); then
  echo "--sample-secs must be >= 2" >&2
  exit 2
fi

WORKDIR="${TMPDIR:-/tmp}/tunmux-proton-bench-$$"
mkdir -p "$WORKDIR"
RESULTS_TSV="$WORKDIR/results.tsv"
LOG_DIR="$WORKDIR/logs"
mkdir -p "$LOG_DIR"

cleanup() {
  :
}
trap cleanup EXIT

status_out="$("$BIN" status || true)"
original_server="$(awk '$2=="proton"{print $3; exit}' <<<"$status_out")"

echo "Original proton server: ${original_server:-<none>}"
echo "Preparing candidate list..."

declare -a candidates=()
if [[ -n "$SERVERS_CSV" ]]; then
  IFS=',' read -r -a raw <<<"$SERVERS_CSV"
  for s in "${raw[@]}"; do
    s="$(xargs <<<"$s")"
    [[ -n "$s" ]] && candidates+=("$s")
  done
else
  list_cmd=("$BIN" proton servers)
  [[ -n "$COUNTRY" ]] && list_cmd+=(--country "$COUNTRY")
  (( P2P == 1 )) && list_cmd+=(--p2p)
  mapfile -t candidates < <(
    "${list_cmd[@]}" \
      | awk 'NF>0 && $1 ~ /^[A-Z]{2}#[0-9]+$/ {print $1}' \
      | head -n "$COUNT"
  )
fi

if (( ${#candidates[@]} == 0 )); then
  echo "No candidate servers found." >&2
  exit 1
fi

echo "Candidates (${#candidates[@]}): ${candidates[*]}"

echo -e "server\tsamples_ok\tsamples_fail\tmean_mib\tstd_mib\tcv_pct\tttfb_ms\tttfb_jitter_ms\tscore" >"$RESULTS_TSV"

disconnect_proton_all() {
  "$BIN" proton disconnect --all >/dev/null 2>&1 || true
}

connect_server() {
  local server="$1"
  "$BIN" proton connect "$server" --local-proxy
}

get_http_port_for_server() {
  local server="$1"
  "$BIN" status | awk -v srv="$server" '$2=="proton" && $3==srv {split($7,a,":"); print a[2]; exit}'
}

calc_stats() {
  awk '
    BEGIN { n=0; mean=0; m2=0; min=""; max="" }
    {
      x=$1+0
      n++
      d=x-mean
      mean+=d/n
      m2+=d*(x-mean)
      if (min=="" || x<min) min=x
      if (max=="" || x>max) max=x
    }
    END {
      if (n==0) { print "0 0 0 0 0"; exit }
      std=(n>1)?sqrt(m2/n):0
      print n, mean, std, min, max
    }
  '
}

for server in "${candidates[@]}"; do
  echo ""
  echo "=== Benchmarking $server ==="

  disconnect_proton_all
  conn_log="$LOG_DIR/connect-${server//[#\/]/_}.log"
  if ! connect_server "$server" >"$conn_log" 2>&1; then
    echo "Connect failed for $server"
    tail -n 30 "$conn_log" || true
    echo -e "${server}\t0\t${SAMPLES}\t0\t0\t0\t0\t0\t-9999" >>"$RESULTS_TSV"
    continue
  fi

  http_port="$(get_http_port_for_server "$server" || true)"
  if [[ -z "$http_port" ]]; then
    echo "Could not resolve HTTP port for $server"
    echo -e "${server}\t0\t${SAMPLES}\t0\t0\t0\t0\t0\t-9999" >>"$RESULTS_TSV"
    continue
  fi

  speed_file="$WORKDIR/speed-${server//[#\/]/_}.txt"
  ttfb_file="$WORKDIR/ttfb-${server//[#\/]/_}.txt"
  : >"$speed_file"
  : >"$ttfb_file"
  fail_count=0

  for i in $(seq 1 "$SAMPLES"); do
    out="$(
      curl -sS -o /dev/null \
        --proxy "http://127.0.0.1:${http_port}" \
        --max-time "$SAMPLE_SECS" \
        -w "%{speed_download} %{time_starttransfer} %{http_code}" \
        "$URL" || true
    )"
    speed="$(awk '{print $1}' <<<"$out")"
    ttfb="$(awk '{print $2}' <<<"$out")"
    code="$(awk '{print $3}' <<<"$out")"

    if [[ "$code" == "200" ]] && awk "BEGIN{exit !($speed>0)}"; then
      echo "$speed" >>"$speed_file"
      echo "$ttfb" >>"$ttfb_file"
      printf 'sample=%d speed_Bps=%s ttfb_s=%s code=%s\n' "$i" "$speed" "$ttfb" "$code"
    else
      fail_count=$((fail_count + 1))
      printf 'sample=%d failed code=%s raw="%s"\n' "$i" "$code" "$out"
    fi
    sleep 1
  done

  read -r n_speed mean_speed std_speed _ _ < <(calc_stats <"$speed_file")
  read -r n_ttfb mean_ttfb std_ttfb _ _ < <(calc_stats <"$ttfb_file")

  mean_mib="$(awk -v v="$mean_speed" 'BEGIN{printf "%.2f", v/1048576}')"
  std_mib="$(awk -v v="$std_speed" 'BEGIN{printf "%.2f", v/1048576}')"
  cv_pct="$(awk -v m="$mean_speed" -v s="$std_speed" 'BEGIN{if (m<=0) print "999.00"; else printf "%.2f", (s/m)*100}')"
  ttfb_ms="$(awk -v v="$mean_ttfb" 'BEGIN{printf "%.2f", v*1000}')"
  ttfb_jitter_ms="$(awk -v v="$std_ttfb" 'BEGIN{printf "%.2f", v*1000}')"
  score="$(
    awk -v mean="$mean_mib" -v cv="$cv_pct" -v tj="$ttfb_jitter_ms" -v fail="$fail_count" \
      'BEGIN{printf "%.2f", mean - (0.70*cv) - (0.05*tj) - (5*fail)}'
  )"

  echo "summary: ok=$n_speed fail=$fail_count mean=${mean_mib}MiB/s std=${std_mib}MiB/s cv=${cv_pct}% ttfb=${ttfb_ms}ms jitter=${ttfb_jitter_ms}ms score=${score}"
  echo -e "${server}\t${n_speed}\t${fail_count}\t${mean_mib}\t${std_mib}\t${cv_pct}\t${ttfb_ms}\t${ttfb_jitter_ms}\t${score}" >>"$RESULTS_TSV"
done

RANKED_TSV="$WORKDIR/ranked.tsv"
{
  head -n 1 "$RESULTS_TSV"
  tail -n +2 "$RESULTS_TSV" | sort -t $'\t' -k9,9nr
} >"$RANKED_TSV"

echo ""
echo "=== Ranking (best first) ==="
cat "$RANKED_TSV"

best_server="$(awk 'NR==2{print $1}' "$RANKED_TSV")"
echo "Best server: ${best_server:-<none>}"

disconnect_proton_all

if (( CONNECT_BEST == 1 )) && [[ -n "${best_server:-}" ]]; then
  echo "Connecting best server: $best_server"
  "$BIN" proton connect "$best_server" --local-proxy
elif (( RESTORE_ORIGINAL == 1 )) && [[ -n "${original_server:-}" ]]; then
  echo "Restoring original server: $original_server"
  "$BIN" proton connect "$original_server" --local-proxy
else
  echo "Leaving Proton disconnected."
fi

echo ""
echo "Results file: $RESULTS_TSV"
