. "$TESTDIR/def.inc"

# Optional override for fake Host/SNI used by hostfakesplit.
# HOSTFAKE is the native hostfakesplit variable and applies to HTTP and HTTPS.
# For HTTPS only, if HOSTFAKE is empty, TLS_MOD_SNI is used as a fallback.
# Values can be set in def.inc / environment or passed as arguments:
#   HOSTFAKE=example.com
#   TLS_MOD_SNI=example.com, tls_mod_sni=example.com, --tls-mod-sni=example.com, sni=example.com
for __arg in "$@"; do
	case "$__arg" in
		HOSTFAKE=*|hostfake=*|--hostfake=*)
			HOSTFAKE="${__arg#*=}"
			;;
		TLS_MOD_SNI=*|tls_mod_sni=*|--tls-mod-sni=*|sni=*)
			TLS_MOD_SNI="${__arg#*=}"
			;;
	esac
done
unset __arg

pktws_hostfake_vary_()
{
	local ok_any=0 testf=$1 domain="$2" fooling="$3" pre="$4" post="$5" disorder hf="${hostfake:-$HOSTFAKE}"
	shift; shift; shift

	for disorder in '' 'disorder_after:'; do
		pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}$fooling:repeats=$FAKE_REPEATS $post && ok_any=1
		pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake1:$fooling:repeats=$FAKE_REPEATS $post && ok_any=1
		pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake2:$fooling:repeats=$FAKE_REPEATS $post && ok_any=1
		pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok_any=1
		pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake1:midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok_any=1
		pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake2:midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok_any=1
	done
	[ "$ok_any" = 1 ] && ok=1
}
pktws_hostfake_vary()
{
	local ok_any=0 fooling="$3"
	pktws_hostfake_vary_ "$1" "$2" "$3" "$4" "$5" && ok_any=1
	# duplicate SYN with MD5
	contains "$fooling" tcp_md5 && \
		pktws_hostfake_vary_  "$1" "$2" "$3" "$4" "${5:+$5 }--payload=empty --out-range=<s1 --lua-desync=send:$TCP_MD5" && ok_any=1
	[ "$ok_any" = 1 ]
}


pktws_check_hostfake()
{
	# $1 - test function
	# $2 - domain
	# $3 - payload_type
	# $4 - PRE args for nfqws2
	local testf=$1 domain="$2" pre="$4"
	local ok ttls attls f fooling
	local PAYLOAD="--payload=$3" hostfake="$HOSTFAKE"

	# hostfakesplit uses host=..., not tls_mod=... . For HTTPS/TLS tests,
	# reuse TLS_MOD_SNI as the fake host only when HOSTFAKE is not explicitly set.
	[ "$3" = tls_client_hello -a -z "$hostfake" ] && hostfake="$TLS_MOD_SNI"

	[ "$MAX_TTL" = 0 ] || ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	[ "$MAX_AUTOTTL_DELTA" = 0 ] || attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	need_hostfakesplit=0
	ok=0
	for ttl in $ttls; do
		# orig-ttl=1 with start/cutoff limiter drops empty ACK packet in response to SYN,ACK. it does not reach DPI or server.
		# missing ACK is transmitted in the first data packet of TLS/HTTP proto
		for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
			pktws_hostfake_vary $testf $domain "ip${IPVV}_ttl=$ttl" "$pre" "$f" && [ "$SCANLEVEL" != force ] && break
		done
		[ "$ok" = 1 ] && break
	done
	for fooling in $FOOLINGS_TCP; do
		pktws_hostfake_vary $testf $domain "$fooling" "$pre"
	done
	for ttl in $attls; do
		for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
			pktws_hostfake_vary $testf $domain "ip${IPVV}_autottl=-$ttl,3-20" "$pre" "$f" && [ "$SCANLEVEL" != force ] && break
		done
	done
	[ $ok = 0 -a "$SCANLEVEL" != force ] && need_hostfakesplit=1
	[ $ok = 1 ]
}

pktws_check_http()
{
	# $1 - test function
	# $2 - domain
	[ "$NOTEST_HOSTFAKE_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	pktws_check_hostfake $1 "$2" http_req
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	pktws_check_hostfake $1 "$2" tls_client_hello "$3"
}
pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_HOSTFAKE_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_check_https_tls "$1" "$2"
	local ret=$?
	[ "$ret" = 0 -a "$SCANLEVEL" != force ] && return
	[ "$NOTEST_WSSIZE_HTTPS" = 1 ] && return $ret

	# do not use 'need' values obtained with wssize
	local need_hostfakesplit_save=$need_hostfakesplit
	pktws_check_https_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
	need_hostfakesplit=$need_hostfakesplit_save
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_HOSTFAKE_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_check_https_tls "$1" "$2"
}
