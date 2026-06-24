. "$TESTDIR/def.inc"

# Optional override for fake Host/SNI used by hostfakesplit and fake TLS.
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
	local testf=$1 domain="$2" fooling="$3" pre="$4" post="$5" disorder hf="${hostfake:-$HOSTFAKE}" fake_tls_mod_arg="${TLS_FAKE_MOD:+:tls_mod=$TLS_FAKE_MOD}"
	shift; shift; shift

	for disorder in '' 'disorder_after:'; do
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling${fake_tls_mod_arg}:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}$fooling:repeats=$FAKE_REPEATS $post && ok=1
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling${fake_tls_mod_arg}:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake1:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling${fake_tls_mod_arg}:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake2:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling${fake_tls_mod_arg}:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling${fake_tls_mod_arg}:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake1:midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling${fake_tls_mod_arg}:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${hf:+host=${hf}:}${disorder}nofake2:midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok=1
	done
}
pktws_hostfake_vary()
{
	local fooling="$3"
	pktws_hostfake_vary_ "$1" "$2" "$3" "$4" "$5"
	# duplicate SYN with MD5
	[ "$NOTEST_OUTRANGE_HTTPS" != 1 -o "$PAYLOAD" != "--payload=tls_client_hello" ] && contains "$fooling" tcp_md5 && \
		pktws_hostfake_vary_  "$1" "$2" "$3" "$4" "${5:+$5 }--payload=empty --out-range=<s1 --lua-desync=send:$TCP_MD5"
}

pktws_check_hostfake()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2
	local testf=$1 domain="$2" pre="$3"
	local ok ttls attls f fooling hostfake="$HOSTFAKE"

	# hostfakesplit uses host=..., not tls_mod=... . For HTTPS/TLS tests,
	# reuse TLS_MOD_SNI as the fake host only when HOSTFAKE is not explicitly set.
	[ "$PAYLOAD" = "--payload=tls_client_hello" -a -z "$hostfake" ] && hostfake="$TLS_MOD_SNI"

	[ "$need_hostfakesplit" = 0 -a "$SCANLEVEL" != force ] && return 0

	[ "$MAX_TTL" = 0 ] || ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	[ "$MAX_AUTOTTL_DELTA" = 0 ] || attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	ok=0
	for ttl in $ttls; do
		for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
			[ "$NOTEST_OUTRANGE_HTTPS" = 1 -a "$PAYLOAD" = "--payload=tls_client_hello" -a -n "$f" ] && continue
			pktws_hostfake_vary $testf $domain "ip${IPVV}_ttl=$ttl" "$pre" "$f" && {
				ok=1
				[ "$SCANLEVEL" = force ] || break
			}
		done
		[ "$ok" = 1 ] && break
	done
	for fooling in $FOOLINGS_TCP; do
		pktws_hostfake_vary $testf $domain "$fooling" "$pre" && ok=1
	done
	for ttl in $attls; do
		for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
			[ "$NOTEST_OUTRANGE_HTTPS" = 1 -a "$PAYLOAD" = "--payload=tls_client_hello" -a -n "$f" ] && continue
			pktws_hostfake_vary $testf $domain "ip${IPVV}_autottl=-$ttl,3-20" "$pre" "$f" && {
				ok=1
				[ "$SCANLEVEL" = force ] || break
			}
		done
	done
	[ "$ok" = 1 ]
}


pktws_check_http()
{
	[ "$NOTEST_FAKE_HOSTFAKE_HTTP" = 1 ] && { echo "SKIPPED"; return 0; }

	local PAYLOAD="--payload=http_req"
	local FAKE="$FAKE_HTTP" TLS_FAKE_MOD=

	if [ -n "$FAKE_HTTP" ]; then
		fake=fake_http
	else
		fake=fake_default_http
	fi

	pktws_check_hostfake "$1" "$2"
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	local PAYLOAD="--payload=tls_client_hello"
	local FAKE="$FAKE_HTTPS" TLS_FAKE_MOD="${TLS_MOD_SNI:+rnd,dupsid,sni=$TLS_MOD_SNI}"

	if [ -n "$FAKE_HTTPS" ]; then
		fake=fake_tls
	else
		fake=fake_default_tls
	fi

	pktws_check_hostfake "$1" "$2" "$3"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKE_HOSTFAKE_HTTPS" = 1 ] && { echo "SKIPPED"; return 0; }

	pktws_check_https_tls "$1" "$2"
	local ret=$?
	[ "$ret" = 0 -a "$SCANLEVEL" != force ] && return
	[ "$NOTEST_WSSIZE_HTTPS" = 1 ] && return $ret
	pktws_check_https_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKE_HOSTFAKE_HTTPS" = 1 ] && { echo "SKIPPED"; return 0; }

	pktws_check_https_tls "$1" "$2"
}
