#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Regression test for commit 0d26aa84ff0b790d7c29c28c791bdf2c0ecdb57a
# "mptcp: avoid dup SUB_CLOSED events after disconnect"
#
# After the initial MPTCP subflow is disconnected due to an error (e.g., TCP
# reset), mptcp_subflow_ctx_reset() resets the close_event_done flag.  When
# another subflow subsequently closes, the kernel worker iterates over all
# subflows and finds the disconnected initial subflow with close_event_done
# cleared, causing a spurious MPTCP_EVENT_SUB_CLOSED event to be emitted with
# a zeroed source address (0.0.0.0) and destination port (0).
#
# The fix avoids this by also checking whether local_id < 0, which is set by
# mptcp_subflow_ctx_reset() during disconnect, before sending the event.
#
# Test scenario:
#  1. Establish an MPTCP connection (initial subflow via 10.0.1.x).
#  2. Add a second subflow endpoint via 10.0.3.x.
#  3. Block MPTCP traffic on 10.0.1.x with iptables (forces RST on initial
#     subflow).
#  4. Wait for the initial subflow to close (SUB_CLOSED #1).
#  5. Add a new subflow endpoint for 10.0.1.x (same blocked network); it
#     fails and generates SUB_CLOSED #2.
#  6. Without the fix a third spurious SUB_CLOSED is emitted for the
#     disconnected initial subflow; with the fix the count stays at 2.

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4
ret=0

ns1=""
ns2=""
evts_file=""
evts_pid=0
srv_pid=0
cli_pid=0

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

log_test()
{
	local msg="$1"
	local rc="$2"

	if [ "$rc" -eq 0 ]; then
		printf "TEST: %-60s  [ OK ]\n" "$msg"
	else
		printf "TEST: %-60s  [FAIL]\n" "$msg"
		ret=1
	fi
}

cleanup()
{
	[ "$evts_pid" -ne 0 ] && kill "$evts_pid" 2>/dev/null
	[ "$srv_pid"  -ne 0 ] && kill "$srv_pid"  2>/dev/null
	[ "$cli_pid"  -ne 0 ] && kill "$cli_pid"  2>/dev/null
	wait 2>/dev/null
	rm -f "$evts_file"
	[ -n "$ns1" ] && ip netns del "$ns1" 2>/dev/null
	[ -n "$ns2" ] && ip netns del "$ns2" 2>/dev/null
}
trap cleanup EXIT

# -----------------------------------------------------------------------
# Prerequisites
# -----------------------------------------------------------------------

check_prereqs()
{
	# Kernel MPTCP support
	if ! [ -f /proc/sys/net/mptcp/enabled ]; then
		echo "SKIP: MPTCP not supported by this kernel"
		exit $ksft_skip
	fi

	# Root privileges required for network namespaces
	if [ "$(id -u)" -ne 0 ]; then
		echo "SKIP: must be run as root"
		exit $ksft_skip
	fi

	# ip mptcp subcommands (requires iproute2 >= 5.14)
	if ! ip mptcp limits show > /dev/null 2>&1; then
		echo "SKIP: ip mptcp not available (need iproute2 >= 5.14)"
		exit $ksft_skip
	fi

	# ip mptcp monitor for event capture
	if ! ip mptcp help 2>&1 | grep -qw monitor; then
		echo "SKIP: ip mptcp monitor not available"
		exit $ksft_skip
	fi

	# iptables for forcing TCP resets
	if ! command -v iptables > /dev/null 2>&1; then
		echo "SKIP: iptables not found"
		exit $ksft_skip
	fi

	# Python3 for creating MPTCP client/server
	if ! command -v python3 > /dev/null 2>&1; then
		echo "SKIP: python3 not found"
		exit $ksft_skip
	fi

	# Verify Python3 can open an MPTCP socket (IPPROTO_MPTCP = 262)
	if ! python3 -c \
		"import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262).close()" \
		> /dev/null 2>&1; then
		echo "SKIP: Python3 cannot create MPTCP sockets"
		exit $ksft_skip
	fi
}

# -----------------------------------------------------------------------
# Network namespace setup
# -----------------------------------------------------------------------

setup_ns()
{
	ns1="mptcp_dup_sub_ns1_$$"
	ns2="mptcp_dup_sub_ns2_$$"

	ip netns add "$ns1" || { echo "FAIL: cannot add netns $ns1"; exit 1; }
	ip netns add "$ns2" || { echo "FAIL: cannot add netns $ns2"; exit 1; }

	# First veth pair – used for the initial subflow (10.0.1.x)
	ip link add ns1eth1 netns "$ns1" type veth peer name ns2eth1 netns "$ns2"
	ip -net "$ns1" addr add 10.0.1.1/24 dev ns1eth1
	ip -net "$ns1" link set ns1eth1 up
	ip -net "$ns1" link set lo up

	ip -net "$ns2" addr add 10.0.1.2/24 dev ns2eth1
	ip -net "$ns2" link set ns2eth1 up
	ip -net "$ns2" link set lo up

	# Second veth pair – used for the second subflow (10.0.3.x)
	ip link add ns1eth3 netns "$ns1" type veth peer name ns2eth3 netns "$ns2"
	ip -net "$ns1" addr add 10.0.3.1/24 dev ns1eth3
	ip -net "$ns1" link set ns1eth3 up

	ip -net "$ns2" addr add 10.0.3.2/24 dev ns2eth3
	ip -net "$ns2" link set ns2eth3 up

	# Allow ns2 to reach ns1's 10.0.1.1 via the 10.0.3.x path as well
	ip -net "$ns2" route add default via 10.0.3.1 dev ns2eth3 metric 103

	# Enable MPTCP
	ip netns exec "$ns1" sysctl -q net.mptcp.enabled=1
	ip netns exec "$ns2" sysctl -q net.mptcp.enabled=1

	# Allow up to 2 additional subflows
	ip netns exec "$ns1" ip mptcp limits set subflows 2 add_addr_accepted 0
	ip netns exec "$ns2" ip mptcp limits set subflows 2 add_addr_accepted 0
}

# -----------------------------------------------------------------------
# Server / client helpers
# -----------------------------------------------------------------------

start_server()
{
	ip netns exec "$ns1" python3 - << 'PYEOF' &
import socket, sys, signal

IPPROTO_MPTCP = 262
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
signal.signal(signal.SIGINT,  lambda *_: sys.exit(0))

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('10.0.1.1', 12000))
srv.listen(1)
srv.settimeout(120)
try:
    conn, _ = srv.accept()
    conn.settimeout(1)
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            conn.send(data)
        except socket.timeout:
            pass
except Exception:
    pass
PYEOF
	srv_pid=$!
	# Give the server a moment to bind and listen
	sleep 0.5
}

start_client()
{
	ip netns exec "$ns2" python3 - << 'PYEOF' &
import socket, sys, time, signal

IPPROTO_MPTCP = 262
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
signal.signal(signal.SIGINT,  lambda *_: sys.exit(0))

cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
try:
    cli.connect(('10.0.1.1', 12000))
    while True:
        cli.send(b'x' * 256)
        time.sleep(0.5)
except Exception:
    pass
PYEOF
	cli_pid=$!
	# Give the client a moment to establish the connection
	sleep 1
}

# -----------------------------------------------------------------------
# Event monitoring helpers
# -----------------------------------------------------------------------

start_events()
{
	evts_file=$(mktemp)
	# Monitor MPTCP events in ns2
	ip netns exec "$ns2" ip mptcp monitor > "$evts_file" 2>&1 &
	evts_pid=$!
	sleep 0.2
}

count_sub_closed()
{
	grep -c "\[SUB_CLOSED\]" "$evts_file" 2>/dev/null || echo 0
}

# Wait until at least $1 SUB_CLOSED events have been recorded (10 s timeout)
wait_sub_closed()
{
	local exp="$1"
	local i

	for i in $(seq 100); do
		[ "$(count_sub_closed)" -ge "$exp" ] && return 0
		sleep 0.1
	done
	return 1
}

# -----------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------

check_prereqs
setup_ns
start_server
start_client
start_events

# Step 1 – Add a second subflow endpoint so that the connection survives
# when the initial subflow is disrupted.
ip netns exec "$ns2" ip mptcp endpoint add 10.0.3.2 subflow
sleep 1

# Step 2 – Reduce TCP retries so that blocked connections fail quickly.
ip netns exec "$ns2" sysctl -q net.ipv4.tcp_syn_retries=1

# Step 3 – Block MPTCP-option traffic on the 10.0.1.x path to force a
# TCP reset on the initial subflow.  TCP option 30 (0x1e) is the MPTCP
# option number.
if ! ip netns exec "$ns1" iptables -A INPUT \
		-s "10.0.1.2" -p tcp --tcp-option 30 \
		-j REJECT --reject-with tcp-reset 2>/dev/null ||
   ! ip netns exec "$ns2" iptables -A INPUT \
		-d "10.0.1.2" -p tcp --tcp-option 30 \
		-j REJECT --reject-with tcp-reset 2>/dev/null; then
	echo "SKIP: iptables --tcp-option not supported"
	exit $ksft_skip
fi

# Step 4 – Wait for the initial subflow (10.0.1.2) to close.
if ! wait_sub_closed 1; then
	log_test "initial subflow closed after reset" 1
	exit $ret
fi
log_test "initial subflow closed after reset" 0

# Step 5 – Try to open a new subflow from 10.0.1.2 (still blocked).
# This will fail and should generate exactly one more SUB_CLOSED event.
ip netns exec "$ns2" ip mptcp endpoint add 10.0.1.2 subflow id 20

# Step 6 – Wait for the second SUB_CLOSED event (the failed new subflow).
if ! wait_sub_closed 2; then
	log_test "failed subflow attempt closed" 1
	exit $ret
fi
log_test "failed subflow attempt closed" 0

# Step 7 – Verify that no spurious third SUB_CLOSED event was emitted.
# Without the fix the kernel re-sends a SUB_CLOSED for the disconnected
# initial subflow when it processes the second subflow closure, yielding
# 3 events total.  With the fix the count must be exactly 2.
count=$(count_sub_closed)
if [ "$count" -eq 2 ]; then
	log_test "no duplicate SUB_CLOSED events after disconnect" 0
else
	printf "FAIL: expected 2 SUB_CLOSED events, got %s\n" "$count"
	echo "--- captured events ---"
	cat "$evts_file"
	echo "--- end of events ---"
	log_test "no duplicate SUB_CLOSED events after disconnect" 1
fi

exit $ret
