FOOLINGS46_TCP=${FOOLINGS46_TCP:-"tcp_md5 badsum tcp_seq=-3000 tcp_seq=1000000 tcp_ack=-66000:tcp_ts_up tcp_ts=-1000 tcp_flags_unset=ACK tcp_flags_set=SYN"}
FOOLINGS6_TCP=${FOOLINGS6_TCP:-"ip6_hopbyhop ip6_hopbyhop:ip6_hopbyhop2 ip6_destopt ip6_routing ip6_ah"}
FOOLINGS_TCP="$FOOLINGS46_TCP"
[ "$IPV" = 6 ] && FOOLINGS_TCP="$FOOLINGS_TCP $FOOLINGS6_TCP"
FOOLINGS6_UDP="${FOOLINGS6_UDP:-$FOOLINGS6_TCP}"
FOOLINGS_UDP="${FOOLINGS_UDP:-badsum}"
[ "$IPV" = 6 ] && FOOLINGS_UDP="$FOOLINGS_UDP $FOOLINGS6_UDP"

FAKE_REPEATS=${FAKE_REPEATS:-1}

# Optional SNI value for TLS ClientHello modification in fake TLS tests.
# Used by 25-fake.sh, 50-fake-multi.sh, 55-fake-faked.sh,
# and by 60-fake-hostfake.sh when adding tls_mod to fake TLS.
# Also used by 35-hostfake.sh / 60-fake-hostfake.sh for HTTPS hostfakesplit
# if HOSTFAKE is empty.
# Examples:
#   TLS_MOD_SNI=example.com
#   ./blockcheck.sh ... TLS_MOD_SNI=example.com
# If empty, existing tls_mod tests stay compatible with the original rnd,dupsid behavior.
TLS_MOD_SNI=${TLS_MOD_SNI:-}

# Optional fake host value for hostfakesplit tests.
# Applies to HTTP and HTTPS. If empty, HTTPS can fall back to TLS_MOD_SNI.
HOSTFAKE=${HOSTFAKE:-}

# Skip the additional HTTPS/TLS1.2 wssize strategy pass in test scripts.
# When enabled, only the normal HTTPS/TLS1.2 pass is executed.
NOTEST_WSSIZE_HTTPS=${NOTEST_WSSIZE_HTTPS:-0}

MIN_TTL=${MIN_TTL:-1}
MAX_TTL=${MAX_TTL:-12}
MIN_AUTOTTL_DELTA=${MIN_AUTOTTL_DELTA:-1}
MAX_AUTOTTL_DELTA=${MAX_AUTOTTL_DELTA:-5}

# can use MULTIDISORER=multidisorder_legacy
MULTIDISORDER=${MULTIDISORDER:-multidisorder}

TCP_MD5=tcp_md5
# OpenBSD can occupy 24 bytes in tcp options in SYN packet leaving no space for the md5 header
[ "$UNAME" = OpenBSD ] && TCP_MD5=$TCP_MD5:tcp_nop_del
