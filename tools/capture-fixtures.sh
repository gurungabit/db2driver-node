#!/usr/bin/env bash
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
CONTAINER="db2-wire-test"
DB="testdb"
USER="db2inst1"
PASSWORD="db2wire_test_pw"
HOST="localhost"
PORT=50000
FIXTURE_DIR="$(cd "$(dirname "$0")/../tests/protocol/fixtures" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Verify prerequisites ──────────────────────────────────────────────────────
if ! command -v tshark &> /dev/null; then
  err "tshark is not installed. Install wireshark-cli / tshark first."
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  err "DB2 container '${CONTAINER}' is not running. Start it first."
  exit 1
fi

mkdir -p "$FIXTURE_DIR"

# ── Capture helper ─────────────────────────────────────────────────────────────
# Usage: capture_fixture <name> <sql_command>
capture_fixture() {
  local name="$1"
  shift
  local sql="$*"
  local pcap_file="$FIXTURE_DIR/${name}.pcap"
  local bin_file="$FIXTURE_DIR/${name}.bin"

  info "Capturing fixture: ${name}"
  info "  SQL: ${sql}"

  # Start tshark capture in background
  tshark -i lo -f "tcp port ${PORT}" -w "$pcap_file" -q &
  local tshark_pid=$!
  sleep 1  # Let tshark initialize

  # Run the SQL command against DB2
  docker exec -i "$CONTAINER" bash -c \
    "su - $USER -c \"db2 connect to $DB > /dev/null 2>&1 && db2 \\\"$sql\\\"\"" \
    > /dev/null 2>&1 || true

  # Give tshark time to capture trailing packets
  sleep 1
  kill "$tshark_pid" 2>/dev/null || true
  wait "$tshark_pid" 2>/dev/null || true

  # Extract raw DRDA payload from pcap
  tshark -r "$pcap_file" -T fields -e data.data -Y "tcp.port == ${PORT}" \
    2>/dev/null | tr -d ':\n' | xxd -r -p > "$bin_file" 2>/dev/null || true

  if [[ -f "$pcap_file" ]]; then
    ok "Captured ${name} -> $(wc -c < "$pcap_file") bytes (pcap)"
  else
    err "Failed to capture ${name}"
  fi
}

# ── Capture fixtures ──────────────────────────────────────────────────────────
info "Starting DRDA fixture capture..."

# 1. Handshake - just connect and disconnect
capture_fixture "handshake" "VALUES 1"

# 2. Simple SELECT
capture_fixture "select_simple" "SELECT id, name, salary FROM employees WHERE id = 1"

# 3. Multi-row SELECT
capture_fixture "select_multirow" "SELECT id, name, dept_id, salary FROM employees ORDER BY id"

# 4. INSERT
capture_fixture "insert" "INSERT INTO accounts (id, name, balance) VALUES (99, 'Fixture', 1234.56)"

# 5. Syntax error
capture_fixture "syntax_error" "SELEKT * FORM nowhere"

# ── Cleanup test data ─────────────────────────────────────────────────────────
info "Cleaning up fixture test data..."
docker exec -i "$CONTAINER" bash -c \
  "su - $USER -c \"db2 connect to $DB > /dev/null 2>&1 && db2 \\\"DELETE FROM accounts WHERE id = 99\\\"\"" \
  > /dev/null 2>&1 || true

ok "All fixtures captured in: ${FIXTURE_DIR}"
ls -la "$FIXTURE_DIR"
