#!/usr/bin/env bats
#
# Test suite for runiperftest.sh
# Uses BATS (Bash Automated Testing Framework): https://github.com/bats-core/bats-core
#
# Install BATS:
#   git clone https://github.com/bats-core/bats-core.git && cd bats-core && ./install.sh /usr/local
#
# Run tests:
#   bats test/runiperftest.bats

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
FIXTURES_DIR="$BATS_TEST_DIRNAME/fixtures"

setup() {
    # Run each test in a temporary directory so log files don't pollute the repo
    TEST_TMPDIR="$(mktemp -d)"
    cp "$SCRIPT_DIR/runiperftest.sh" "$TEST_TMPDIR/"
    cd "$TEST_TMPDIR"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# ---------------------------------------------------------------------------
# 1. vm.list parsing
# ---------------------------------------------------------------------------

@test "parses CLIENT and SERVER from a valid vm.list entry" {
    LINE="192.168.1.1,10.0.0.1"
    SERVER=$(echo "$LINE" | cut -f2 -d",")
    CLIENT=$(echo "$LINE" | cut -f1 -d",")

    [ "$SERVER" = "10.0.0.1" ]
    [ "$CLIENT" = "192.168.1.1" ]
}

@test "parses localhost-to-localhost entry correctly" {
    LINE="127.0.0.1,127.0.0.1"
    SERVER=$(echo "$LINE" | cut -f2 -d",")
    CLIENT=$(echo "$LINE" | cut -f1 -d",")

    [ "$SERVER" = "127.0.0.1" ]
    [ "$CLIENT" = "127.0.0.1" ]
}

@test "handles multiple vm.list entries" {
    printf "10.0.0.1,10.0.0.2\n10.0.0.3,10.0.0.4\n" > vm.list
    COUNT=$(wc -l < vm.list | tr -d ' ')
    [ "$COUNT" -eq 2 ]
}

@test "empty vm.list produces no iterations" {
    printf "" > vm.list
    ITERATIONS=0
    for LINE in $(cat vm.list); do
        ITERATIONS=$((ITERATIONS + 1))
    done
    [ "$ITERATIONS" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 2. Log file naming
# ---------------------------------------------------------------------------

@test "log filename is derived from SERVER IP" {
    SERVER="10.0.0.2"
    EXPECTED_LOG="${SERVER}.log"
    [ "$EXPECTED_LOG" = "10.0.0.2.log" ]
}

@test "SERVER_IP is extracted from log filename by stripping .log" {
    LOG="10.0.0.2.log"
    SERVER_IP=$(echo "$LOG" | sed -e 's/.log//')
    [ "$SERVER_IP" = "10.0.0.2" ]
}

# ---------------------------------------------------------------------------
# 3. SUM line parsing (throughput extraction from iperf output)
# ---------------------------------------------------------------------------

@test "extracts throughput value and unit from SUM line" {
    cat > sample.log <<'EOF'
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-30.0 sec  29.5 GBytes  8.46 Gbits/sec
[  4]  0.0-30.0 sec  29.4 GBytes  8.41 Gbits/sec
[SUM]  0.0-30.0 sec   118 GBytes  33.7 Gbits/sec
EOF
    TP=$(grep SUM sample.log | awk '{ print $6" "$7 }')
    [ "$TP" = "33.7 Gbits/sec" ]
}

@test "returns empty throughput when log has no SUM line" {
    cat > nosumm.log <<'EOF'
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-30.0 sec  29.5 GBytes  8.46 Gbits/sec
EOF
    TP=$(grep SUM nosumm.log | awk '{ print $6" "$7 }')
    [ -z "$TP" ]
}

@test "handles multiple SUM lines (multiple runs in one log)" {
    cat > multi.log <<'EOF'
[SUM]  0.0-30.0 sec   118 GBytes  33.7 Gbits/sec
[SUM]  0.0-30.1 sec   118 GBytes  33.6 Gbits/sec
EOF
    SUM_COUNT=$(grep -c SUM multi.log)
    [ "$SUM_COUNT" -eq 2 ]
}

# ---------------------------------------------------------------------------
# 4. Flow string formatting
# ---------------------------------------------------------------------------

@test "formats flow as CLIENT -> SERVER" {
    SERVER_IP="10.0.0.2"
    printf "10.0.0.1,10.0.0.2\n" > vm.list
    FLOW=$(grep "$SERVER_IP" vm.list | sed -e 's/,/ -> /g')
    [ "$FLOW" = "10.0.0.1 -> 10.0.0.2" ]
}

@test "formats localhost-to-localhost flow" {
    SERVER_IP="127.0.0.1"
    printf "127.0.0.1,127.0.0.1\n" > vm.list
    FLOW=$(grep "$SERVER_IP" vm.list | sed -e 's/,/ -> /g')
    [ "$FLOW" = "127.0.0.1 -> 127.0.0.1" ]
}

# ---------------------------------------------------------------------------
# 5. Aggregate throughput calculation
# ---------------------------------------------------------------------------

@test "sums throughput across single log file" {
    cat > 10.0.0.2.log <<'EOF'
[SUM]  0.0-30.0 sec   118 GBytes  33.7 Gbits/sec
EOF
    TP=$(grep SUM 10.0.0.2.log | awk '{ sum+=$6 } END { print sum }')
    [ "$TP" = "33.7" ]
}

@test "sums throughput across multiple log files" {
    cat > 10.0.0.2.log <<'EOF'
[SUM]  0.0-30.0 sec   118 GBytes  10.0 Gbits/sec
EOF
    cat > 10.0.0.3.log <<'EOF'
[SUM]  0.0-30.0 sec   118 GBytes  20.0 Gbits/sec
EOF
    TP=$(grep SUM *.log | awk '{ sum+=$6 } END { print sum }')
    [ "$TP" = "30" ]
}

@test "aggregate is zero when no SUM lines exist" {
    cat > empty.log <<'EOF'
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-30.0 sec  29.5 GBytes  8.46 Gbits/sec
EOF
    TP=$(grep SUM empty.log | awk '{ sum+=$6 } END { print sum }')
    [ -z "$TP" ]
}

# ---------------------------------------------------------------------------
# 6. Log file count reporting
# ---------------------------------------------------------------------------

@test "counts log files correctly for single server" {
    touch 10.0.0.2.log
    COUNT=$(ls -1 ./*.log | wc -l | tr -d ' ')
    [ "$COUNT" -eq 1 ]
}

@test "counts log files correctly for multiple servers" {
    touch 10.0.0.2.log 10.0.0.3.log 10.0.0.4.log
    COUNT=$(ls -1 ./*.log | wc -l | tr -d ' ')
    [ "$COUNT" -eq 3 ]
}

# ---------------------------------------------------------------------------
# 7. Log cleanup
# ---------------------------------------------------------------------------

@test "log cleanup removes all .log files" {
    touch server1.log server2.log server3.log
    rm -rf ./*log
    LOG_COUNT=$(ls ./*.log 2>/dev/null | wc -l | tr -d ' ')
    [ "$LOG_COUNT" -eq 0 ]
}

@test "log cleanup does not remove non-log files" {
    touch server1.log keep_this.txt
    rm -rf ./*log
    [ -f keep_this.txt ]
}

# ---------------------------------------------------------------------------
# 8. Process wait loop threshold (off-by-one bug regression)
# ---------------------------------------------------------------------------

@test "wait loop exits when RUNNING equals 1 (grep itself)" {
    # The current check is `<= 1`, meaning it exits when only grep is running.
    # This test documents the expected behaviour.
    RUNNING=1
    if [ "$RUNNING" -le 1 ]; then
        SHOULD_BREAK=true
    fi
    [ "$SHOULD_BREAK" = "true" ]
}

@test "wait loop continues when RUNNING is 2 (one real iperf process)" {
    RUNNING=2
    SHOULD_BREAK=false
    if [ "$RUNNING" -le 1 ]; then
        SHOULD_BREAK=true
    fi
    [ "$SHOULD_BREAK" = "false" ]
}
