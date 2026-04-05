#!/usr/bin/env bash
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
CONTAINER="db2-wire-test"
DB="testdb"
USER="db2inst1"
COMPOSE_FILE="$(cd "$(dirname "$0")/../docker" && pwd)/docker-compose.yml"
SEED_DIR="$(cd "$(dirname "$0")/../docker/seed" && pwd)"
TIMEOUT=300

# ── Colors ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── ARM detection ──────────────────────────────────────────────────────────────
check_arch() {
  local arch
  arch="$(uname -m)"
  if [[ "$arch" == "arm64" || "$arch" == "aarch64" ]]; then
    warn "DB2 container image may not support ARM ($arch) natively."
    warn "Performance may be degraded under emulation."
  fi
}

# ── Wait for DB2 readiness ─────────────────────────────────────────────────────
wait_for_db2() {
  info "Waiting for DB2 to become ready (timeout: ${TIMEOUT}s)..."
  local elapsed=0
  local interval=5
  while (( elapsed < TIMEOUT )); do
    if docker exec "$CONTAINER" bash -c "su - $USER -c 'db2 connect to $DB'" > /dev/null 2>&1; then
      ok "DB2 is ready after ${elapsed}s"
      return 0
    fi
    sleep "$interval"
    elapsed=$(( elapsed + interval ))
    info "Still waiting... (${elapsed}s / ${TIMEOUT}s)"
  done
  err "DB2 did not become ready within ${TIMEOUT}s"
  return 1
}

# ── Commands ───────────────────────────────────────────────────────────────────
cmd_start() {
  check_arch
  info "Starting DB2 container..."
  docker compose -f "$COMPOSE_FILE" up -d
  wait_for_db2
  ok "DB2 is up and running"
}

cmd_stop() {
  info "Stopping DB2 container..."
  docker compose -f "$COMPOSE_FILE" down
  ok "DB2 stopped"
}

cmd_status() {
  if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    if docker exec "$CONTAINER" bash -c "su - $USER -c 'db2 connect to $DB'" > /dev/null 2>&1; then
      ok "DB2 is running and accepting connections"
      return 0
    else
      warn "DB2 container is running but database is not ready"
      return 1
    fi
  else
    err "DB2 container is not running"
    return 1
  fi
}

cmd_seed() {
  info "Seeding database..."
  for sql_file in "$SEED_DIR"/*.sql; do
    local fname
    fname="$(basename "$sql_file")"
    info "Running $fname..."
    docker exec -i "$CONTAINER" bash -c "su - $USER -c 'db2 -tvf /seed/$fname'" || {
      err "Failed to run $fname"
      return 1
    }
  done
  ok "Database seeded successfully"
}

cmd_reset() {
  info "Resetting database..."
  cmd_stop 2>/dev/null || true
  info "Removing volume..."
  docker volume rm docker_db2data 2>/dev/null || true
  cmd_start
  cmd_seed
  ok "Database reset complete"
}

cmd_sql() {
  if [[ $# -eq 0 ]]; then
    err "Usage: $0 sql <SQL statement>"
    return 1
  fi
  local sql="$*"
  docker exec -i "$CONTAINER" bash -c "su - $USER -c \"db2 connect to $DB > /dev/null && db2 \\\"$sql\\\"\""
}

cmd_exec() {
  if [[ $# -eq 0 ]]; then
    err "Usage: $0 exec <command>"
    return 1
  fi
  docker exec -it "$CONTAINER" bash -c "su - $USER -c '$*'"
}

cmd_capture() {
  info "Capturing DRDA protocol fixtures..."
  local capture_script
  capture_script="$(cd "$(dirname "$0")" && pwd)/capture-fixtures.sh"
  if [[ -x "$capture_script" ]]; then
    "$capture_script"
  else
    err "capture-fixtures.sh not found or not executable"
    return 1
  fi
}

cmd_logs() {
  docker logs "$CONTAINER" "$@"
}

# ── Usage ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [args...]

Commands:
  start     Start the DB2 container and wait for readiness
  stop      Stop the DB2 container
  status    Check if DB2 is running and accepting connections
  seed      Run seed SQL scripts against the database
  reset     Stop, remove volume, restart, and re-seed
  sql       Run a SQL statement (e.g., ./db2.sh sql "SELECT * FROM employees")
  exec      Execute a command inside the DB2 container
  capture   Capture DRDA protocol fixtures with tshark
  logs      Show container logs (pass docker logs flags)
EOF
}

# ── Main ───────────────────────────────────────────────────────────────────────
case "${1:-}" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  status)  cmd_status ;;
  seed)    cmd_seed ;;
  reset)   cmd_reset ;;
  sql)     shift; cmd_sql "$@" ;;
  exec)    shift; cmd_exec "$@" ;;
  capture) cmd_capture ;;
  logs)    shift; cmd_logs "$@" ;;
  *)       usage; exit 1 ;;
esac
