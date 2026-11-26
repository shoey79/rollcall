#!/bin/sh
# Rollcall agent for OpenWrt and other small BusyBox systems: a shell script, so nothing needs installing.
#
# Reports to the Rollcall add-on every 5 minutes (cron): uptime, CPU, memory, load, storage, network
# interfaces and their traffic, the internet (WAN) connections, OpenWrt's services, and failed
# sign-ins to SSH (dropbear) and the web interface (LuCI). Uses only what OpenWrt has built in:
# /proc, /sys, ubus, jsonfilter, logread and uclient-fetch (or curl / BusyBox wget elsewhere).
#
#   sh rollcall-agent.sh --install     copy to /etc/rollcall, run every 5 minutes, keep through sysupgrade
#   sh rollcall-agent.sh --uninstall   remove it again
#   sh rollcall-agent.sh --report      print the report instead of sending it
#   sh rollcall-agent.sh               send one report now
#
# The first report asks to join; approve it in the Rollcall dashboard (Manage > Agents).
# Downloaded from the dashboard, the add-on's address and enrolment key are already filled in.

AGENT_VERSION="1.0.5"
SERVER="__PM_SERVER__"
ENROL_KEY="__PM_ENROL_KEY__"
IGNORE_CERT=0
# Rollcall's own HTTPS certificate authority, built in when the script is downloaded with HTTPS on. Only this is
# trusted; a certificate in a reply never replaces it (replies aren't signed, and this agent can't check them).
TLS_CA='__PM_TLS_CA__'
umask 077   # everything this agent writes (its token, the report it sends) is root's only

R="${RC_ROOT:-}"   # tests only: a folder standing in for / (OpenWrt's files under it)
DIR="${RC_DIR:-/etc/rollcall}"
STATE="$DIR/token"
PEM="$DIR/rollcall.pem"; TLSPORT="$DIR/tls_port"   # Rollcall's own HTTPS: its certificate and port (1.0.3)
LOG="${RC_LOG:-/tmp/rollcall-agent.log}"
[ -L "$LOG" ] && rm -f "$LOG"   # never append through a link someone left at the fixed name
RUN="${RC_RUN:-/tmp}"            # RAM: the run lock, and where the system log was read up to
SINCE="$RUN/rollcall-since"      # in RAM, not flash: written every run, and the log it marks is in RAM too
LOCK="$RUN/rollcall.lock"
CRON="${RC_CRONTAB:-/etc/crontabs/root}"
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/rollcall.XXXXXX" 2>/dev/null) || { TMPD="${TMPDIR:-/tmp}/rollcall.$$"; rm -rf "$TMPD"; mkdir -m 700 "$TMPD" || exit 1; }
TMP="$TMPD/r"   # a private folder: its files aren't at names others could guess
ERRORS=""
LOGREAD=logread; [ -x "$R/sbin/logread" ] && LOGREAD="$R/sbin/logread"   # OpenWrt's own (ubox), which has -t; not BusyBox's

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; [ -t 1 ] && echo "$*"
    # /tmp is RAM: once the log passes 32 KB, keep its last 16 KB (whole lines)
    [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 32768 ] && tail -c 16384 "$LOG" | sed 1d > "$LOG.new" && mv "$LOG.new" "$LOG"
    return 0
}
err() { ERRORS="$ERRORS${ERRORS:+,}$(js "$1")"; }
have() { command -v "$1" >/dev/null 2>&1; }
# HTTPS needs curl built with TLS, or uclient-fetch with its TLS library (libustream-mbedtls, -openssl or -wolfssl),
# which many routers don't have room for. Without either, this agent stays on plain HTTP and tells Rollcall so.
tls_ok() {
    if have curl; then curl --version 2>/dev/null | head -1 | grep -qiE 'ssl|tls' && return 0; fi
    have uclient-fetch || return 1
    for f in /lib/libustream-ssl*.so* /usr/lib/libustream-ssl*.so*; do [ -e "$f" ] && return 0; done   # each on its own
    return 1
}

# A JSON string: backslashes, quotes and control characters escaped, at most $2 characters.
js() {
    printf '%s' "$1" | head -c "${2:-240}" | tr -d '\000-\010\013\014\016-\037' |
        sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r//g' | awk 'BEGIN{ORS=""} {if (NR>1) print "\\n"; print}' |
        { printf '"'; cat; printf '"'; }
}
bbver() {  # "BusyBox v1.36.1". OpenWrt's BusyBox prints no help, so read it from the program itself.
    v=$( { busybox --help; busybox; } 2>&1 | grep -o '^BusyBox v[0-9.]*' | head -1)
    [ -n "$v" ] || { b=$(command -v busybox) && v=$(tr -c '[:print:]' '\n' < "$b" | grep -o 'BusyBox v[0-9][0-9.]*' | head -1); }
    # otherwise the package's version (opkg, or apk from OpenWrt 25)
    [ -n "$v" ] || v=$(awk '/^Package: busybox$/{p=1;next} /^Package:/{p=0} p&&/^Version:/{print "BusyBox v"$2;exit}' "$R/usr/lib/opkg/status" 2>/dev/null)
    [ -n "$v" ] || v=$(awk '/^P:busybox$/{p=1;next} /^P:/{p=0} p&&/^V:/{print "BusyBox v"substr($0,3);exit}' "$R/lib/apk/db/installed" 2>/dev/null)
    echo "${v:-sh}"
}
join() { awk 'BEGIN{ORS=""} NR>1{print ","} {print}'; }   # lines -> a,b,c (BusyBox on OpenWrt has no paste)
# logread -t adds "[seconds.ms]" to each line; this prints that number (0 if there isn't one)
stamp() { awk '{t=0; for (i=1;i<=NF;i++) if ($i ~ /^\[[0-9]+(\.[0-9]+)?\]$/) {t=$i; gsub(/[^0-9.]/,"",t); break}; print int(t)}'; }
jl() { js "$@"; echo; }   # js, one per line, for building lists with join
num() { case "$1" in ''|*[!0-9.-]*) echo null ;; *) echo "$1" ;; esac; }
utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# --- what this router is -----------------------------------------------------------------------------
system_info() {
    host=$(uci -q get system.@system[0].hostname 2>/dev/null || cat /proc/sys/kernel/hostname)
    HOSTNAME=${host:-router}
    kernel=$(uname -r)
    if [ -f "$R/etc/openwrt_release" ]; then
        . "$R/etc/openwrt_release"
        os="$DISTRIB_DESCRIPTION"; os_id="openwrt"; os_ver="$DISTRIB_RELEASE"
    elif [ -f /etc/os-release ]; then
        os=$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release)
        os_id=$(sed -n 's/^ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release)
        os_ver=$(sed -n 's/^VERSION_ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release)
    fi
    model=$(cat "$R/tmp/sysinfo/model" 2>/dev/null || cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\000')
    up=$(cut -d' ' -f1 /proc/uptime | cut -d. -f1)
    now=$(date +%s)
    boot=$(date -u -d "@$((now - up))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || utc)
    mt=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)
    mf=$(awk '/^MemAvailable:/{a=$2} /^MemFree:/{f=$2} /^Buffers:/{b=$2} /^Cached:/{c=$2} END{print int((a?a:f+b+c)/1024)}' /proc/meminfo)
    set -- $(cat /proc/loadavg)
    load="[$(num "$1"),$(num "$2"),$(num "$3")]"
    cores=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
    # CPU use over a second, from /proc/stat
    s1=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5+$6}' /proc/stat); sleep 1
    s2=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5+$6}' /proc/stat)
    cpu=$(echo "$s1 $s2" | awk '{t=$3-$1; i=$4-$2; if (t>0) printf "%.1f", 100*(t-i)/t; else print "null"}')
    ips=$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')
    [ -z "$ips" ] && ips=$(ifconfig 2>/dev/null | sed -n 's/.*inet addr:\([0-9.]*\).*/\1/p' | grep -v '^127\.')
    ipj=$(for i in $ips; do jl "$i"; done | head -8 | join)
    printf '"hostname":%s,"fqdn":%s,"os":%s,"os_build":%s,"os_id":%s,"os_version_id":%s,"hw_model":%s,"hw_vendor":"","virtual":null,' \
        "$(js "$HOSTNAME" 60)" "$(js "$HOSTNAME" 120)" "$(js "$os (kernel $kernel)" 120)" "$(js "$kernel" 60)" "$(js "$os_id" 30)" "$(js "$os_ver" 20)" "$(js "$model" 80)"
    printf '"boot_time":"%s","uptime_s":%s,"mem_total_mb":%s,"mem_free_mb":%s,"load":%s,"cpu_cores":%s,"cpu_pct":%s,"ips":[%s],' \
        "$boot" "$(num "$up")" "$(num "$mt")" "$(num "$mf")" "$load" "$(num "$cores")" "$cpu" "$ipj"
    printf '"domain":"","part_of_domain":false,"workstation":false,"pending_reboot":false,"updates_pending":null,"security_updates":null,'
}

# --- storage: the overlay (where settings and packages live), plus anything mounted -------------------
disks() {
    df -kP 2>/dev/null | awk 'NR>1 && $2>0 {print $6, $2, $4, $1}' | while read -r mnt size free dev; do
        case "$mnt" in /|/overlay|/rom|/mnt/*|/srv*|/data*|/opt*) ;; *) continue ;; esac
        [ "$mnt" = "/rom" ] && continue   # read-only firmware: always full
        [ "$mnt" = "/" ] && [ "$dev" = "overlayfs:/overlay" ] && continue   # the same space as /overlay
        printf '{"name":%s,"label":%s,"size_gb":%s,"free_gb":%s}\n' "$(js "$mnt")" "$(js "$dev" 80)" \
            "$(awk "BEGIN{printf \"%.3f\", $size/1048576}")" "$(awk "BEGIN{printf \"%.3f\", $free/1048576}")"
    done | join
}

# --- network interfaces, with traffic counters ----------------------------------------------------------
nics() {
    for d in /sys/class/net/*; do
        n=${d##*/}
        case "$n" in lo|ifb*|dummy*|teql*|gre0|gretap0|erspan0|ip6tnl0|sit0|ip6gre0|ip_vti0|ip6_vti0) continue ;; esac
        flags=$(cat "$d/flags" 2>/dev/null); oper=$(cat "$d/operstate" 2>/dev/null); carrier=$(cat "$d/carrier" 2>/dev/null)
        if [ $(( ${flags:-1} & 1 )) -eq 0 ]; then st=disabled
        elif [ "$oper" = up ] || { [ "$oper" = unknown ] && [ "$carrier" = 1 ]; }; then st=up
        else st=down; fi
        speed=0; [ "$st" = up ] && speed=$(cat "$d/speed" 2>/dev/null); case "$speed" in ''|-*|*[!0-9]*) speed=0 ;; esac
        virt=true; [ -e "$d/device" ] && virt=false
        drv=""; [ -e "$d/device/uevent" ] && drv=$(sed -n 's/^DRIVER=//p' "$d/device/uevent")
        ipj=$(ip -o addr show dev "$n" 2>/dev/null | awk '{print $4}' | grep -v '^fe80\|^127\.\|^::1' | while read -r a; do jl "$a"; done | head -8 | join)
        printf '{"name":%s,"desc":%s,"status":"%s","speed_mbps":%s,"mac":%s,"virtual":%s,"media":"","ips":[%s]' \
            "$(js "$n" 80)" "$(js "$drv" 120)" "$st" "$speed" "$(js "$(cat "$d/address" 2>/dev/null)" 40)" "$virt" "$ipj"
        for k in rx_bytes:rx_bytes tx_bytes:tx_bytes rx_errors:rx_errors tx_errors:tx_errors rx_drops:rx_dropped tx_drops:tx_dropped; do
            v=$(cat "$d/statistics/${k#*:}" 2>/dev/null); case "$v" in ''|*[!0-9]*) ;; *) printf ',"%s":%s' "${k%%:*}" "$v" ;; esac
        done
        printf '}\n'
    done | head -40 | join
}

# --- internet (WAN) connections: OpenWrt's logical interfaces with a default route ----------------------
wan() {
    have ubus && have jsonfilter || return 0
    for i in $(ubus -t 10 list 'network.interface.*' 2>/dev/null | sed 's/^network\.interface\.//'); do
        case "$i" in loopback|lan) continue ;; esac
        s=$(ubus -t 10 call "network.interface.$i" status 2>/dev/null) || continue
        g() { echo "$s" | jsonfilter -e "$1" 2>/dev/null | head -1; }
        proto=$(g '@.proto'); [ "$proto" = none ] && continue
        auto=$(g '@.autostart'); up=$(g '@.up')
        dflt=$( { echo "$s" | jsonfilter -e '@.route[*].target'; echo "$s" | jsonfilter -e '@.inactive.route[*].target'; } 2>/dev/null | grep -c '^0\.0\.0\.0$\|^::$')
        case "$i" in wan*|WAN*) ;; *) [ "${dflt:-0}" -gt 0 ] || continue ;; esac
        printf '{"name":%s,"proto":%s,"up":%s,"autostart":%s,"uptime_s":%s,"device":%s,"ipv4":%s,"ipv6":%s,"gateway":%s,"dns":[%s],"error":%s}\n' \
            "$(js "$i" 40)" "$(js "$proto" 20)" "${up:-false}" "${auto:-true}" "$(num "$(g '@.uptime')")" "$(js "$(g '@.l3_device')" 40)" \
            "$(js "$(g '@["ipv4-address"][0].address')" 40)" "$(js "$(g '@["ipv6-address"][0].address')" 60)" \
            "$(js "$( { echo "$s" | jsonfilter -e '@.route[@.target="0.0.0.0"].nexthop'; } 2>/dev/null | head -1)" 40)" \
            "$(echo "$s" | jsonfilter -e '@["dns-server"][*]' 2>/dev/null | head -4 | while read -r d; do jl "$d" 60; done | join)" \
            "$(js "$(g '@.errors[0].code')" 80)"
    done | head -10 | join
}

# --- OpenWrt services (procd): the enabled ones that should be running ---------------------------------
services() {
    have ubus && have jsonfilter || return 0
    for f in "$R"/etc/rc.d/S*; do
        [ -e "$f" ] || continue
        n=${f##*/S[0-9][0-9]}
        r=$(ubus -t 10 call service list "{\"name\":\"$n\"}" 2>/dev/null | jsonfilter -e '@.*.instances.*.running' 2>/dev/null)
        [ -z "$r" ] && continue   # one-off start-up scripts (e.g. boot, sysctl) have nothing running
        state=Running; echo "$r" | grep -q false && state=Stopped
        printf '{"name":%s,"display":%s,"state":"%s","start_mode":"Auto","role":"OpenWrt"}\n' "$(js "$n" 60)" "$(js "$n" 60)" "$state"
    done | head -60 | join
}

# --- failed sign-ins (dropbear SSH, LuCI) since the last report -----------------------------------------
security() {
    have "$LOGREAD" || { printf '{"failed_logons":{"count":0,"top":[]},"items":[]}'; return; }
    since=$(cat "$SINCE" 2>/dev/null || echo 0)
    "$LOGREAD" -t 2>/dev/null | awk -v since="$since" '
        { t = 0; for (i = 1; i <= NF; i++) if ($i ~ /^\[[0-9]+(\.[0-9]+)?\]$/) { t = $i; gsub(/[^0-9.]/, "", t); t = int(t); break } }
        t == 0 || t <= since { next }
        /dropbear.*Bad password attempt for/ { if (match($0, /for .* from [^ ]+/)) { s = substr($0, RSTART + 4, RLENGTH - 4); split(s, p, " from "); a = p[1]; f = p[2] } r = "wrong password"; sub(/:[0-9]+$/, "", f) }
        /dropbear.*Login attempt for nonexistent user/ { a = "(no such user)"; f = $NF; sub(/:[0-9]+$/, "", f); r = "user name does not exist" }
        /dropbear.*(Bad password attempt|nonexistent user)/ || /luci: failed login/ {
            if (/luci: failed login/) { a = $0; sub(/.* for /, "", a); sub(/ from .*/, "", a); f = $NF; r = "wrong password"; v = "LuCI" } else v = "SSH"
            gsub(/'"'"'/, "", a); k = a "|" f "|" r "|" v; c[k]++; n++ }
        END { printf "%d\n", n; for (k in c) print c[k] "|" k }' > "$TMP.sec"
    total=$(head -1 "$TMP.sec")
    top=$(tail -n +2 "$TMP.sec" | sort -t'|' -k1,1nr | head -5 | while IFS='|' read -r c a f r v; do
        printf '{"account":%s,"source":%s,"count":%s,"reason":%s,"type":"network","via":%s}\n' "$(js "$a" 80)" "$(js "$f" 60)" "$c" "$(js "$r" 60)" "$(js "$v" 20)"
    done | join)
    printf '{"failed_logons":{"count":%s,"top":[%s]},"items":[],"admins":[]}' "${total:-0}" "$top"
    rm -f "$TMP.sec"
}

build_report() {
    started=$(date +%s)
    tls=false; tls_ok && tls=true
    printf '{"agent_version":"%s","agent_kind":"sh","os_family":"linux","ps_version":%s,"collected":"%s","tls_capable":%s,' \
        "$AGENT_VERSION" "$(js "$(bbver)" 60)" "$(utc)" "$tls"
    system_info || err "system info failed"
    printf '"disks":[%s],' "$(disks)"
    sv=$(services) || err "services failed"
    printf '"services":{"watched":[%s],"stopped_auto":[]},' "$sv"
    roles="\"Router (OpenWrt)\""; [ -f "$R/etc/openwrt_release" ] || roles="\"Router\""
    ls /sys/class/net 2>/dev/null | grep -q '^wg' && roles="$roles,\"WireGuard\""
    printf '"roles":[%s],"events":{"counts":{},"recent":[]},"sessions":[],' "$roles"
    printf '"security":%s,' "$(security)"
    n=$(nics) || err "network interfaces failed"
    w=$(wan) || err "WAN status failed"
    c=""
    [ -n "$n" ] && c="\"nics\":{\"adapters\":[$n]}"
    [ -n "$w" ] && c="$c${c:+,}\"wan\":{\"interfaces\":[$w]}"
    printf '"checks":{%s},' "$c"
    printf '"errors":[%s],"run_ms":%s}' "$ERRORS" "$(( ($(date +%s) - started) * 1000 ))"
}

# --- talking to Rollcall ---------------------------------------------------------------------------------
# post PATH FILE: prints the HTTP status, and the reply into $TMP.reply. The report carries the agent's token
# in the JSON ("agent_token") rather than an Authorization header: OpenWrt's uclient-fetch can't add headers.
post() {
    url="$SRV$1"; rm -f "$TMP.reply"
    if have curl; then
        set -- -sS -o "$TMP.reply" -w '%{http_code}' -m 30 -H 'Content-Type: application/json' --data-binary "@$2"
        [ "$IGNORE_CERT" = 1 ] && set -- "$@" -k
        [ -n "$CA" ] && set -- "$@" --cacert "$CA"
        code=$(curl "$@" "$url" 2>"$TMP.err"); echo "${code:-000}" | tail -c 4 | head -c 3; echo
        return
    fi
    # uclient-fetch (OpenWrt's wget) or BusyBox wget: 2xx is success; the error text gives the code
    w=wget; have uclient-fetch && w=uclient-fetch
    set -- -T 30 -O "$TMP.reply" --post-file="$2"   # not -q: uclient-fetch would hide "HTTP error 401"
    [ "$IGNORE_CERT" = 1 ] && set -- "$@" --no-check-certificate
    [ -n "$CA" ] && set -- "$@" --ca-certificate="$CA"
    if "$w" "$@" "$url" 2>"$TMP.err"; then
        grep -q '"pending"' "$TMP.reply" 2>/dev/null && echo 202 || echo 200
    else
        code=$(grep -o 'HTTP error [0-9]*\|HTTP/1\.[01] [0-9]*\|error [0-9][0-9][0-9]' "$TMP.err" | grep -o '[0-9][0-9][0-9]$' | head -1)
        echo "${code:-000}"
    fi
}

# Rollcall's own HTTPS. The certificate authority built into this script is the one trusted. A reply only says which
# port: someone on the network could change that, but without Rollcall's key they can't answer on it. A copy of
# the script without it built in (downloaded with HTTPS off) trusts the first one Rollcall sends, once, and never
# replaces it. Nothing in a reply turns HTTPS off: if Rollcall stops answering on its port, plain HTTP is next.
tls_builtin() {
    case "$TLS_CA" in *"BEGIN CERTIFICATE"*) ;; *) return 1 ;; esac
    mkdir -p "$DIR"
    printf '%s\n' "$TLS_CA" > "$TMP.ca"
    cmp -s "$TMP.ca" "$PEM" || { cp "$TMP.ca" "$PEM"; chmod 600 "$PEM"; }
}
tls_reply() {
    have jsonfilter || return 0
    port=$(jsonfilter -i "$TMP.reply" -e '@.tls.port' 2>/dev/null)
    case "$port" in ''|*[!0-9]*) return 0 ;; esac
    if [ ! -s "$PEM" ]; then
        jsonfilter -i "$TMP.reply" -e '@.tls_cert' 2>/dev/null > "$TMP.pem"
        grep -q 'BEGIN CERTIFICATE' "$TMP.pem" || return 0
        cp "$TMP.pem" "$PEM"; chmod 600 "$PEM"
        log "Rollcall's HTTPS is on: reports go to port $port from the next run, trusting only the certificate it sent now (download the agent again to have it built in)"
    fi
    [ "$(cat "$TLSPORT" 2>/dev/null)" = "$port" ] || echo "$port" > "$TLSPORT"
}

send() {
    tls_builtin
    [ -s "$STATE" ] || { mkdir -p "$DIR"; tr -dc 'a-f0-9' < /dev/urandom | head -c 64 > "$STATE"; chmod 600 "$STATE"; }
    token=$(cat "$STATE")
    build_report > "$TMP.body"   # not in a pipe: it sets HOSTNAME
    { printf '{"agent_token":"%s",' "$token"; tail -c +2 "$TMP.body"; } > "$TMP.json"
    # With Rollcall's own HTTPS on, each http:// address's HTTPS twin (same address, its port) is tried first,
    # trusting only Rollcall's certificate; the http:// address stays as the fallback.
    list=""
    for SRV in $(echo "$SERVER" | tr ',;' '  '); do
        SRV=${SRV%/}
        case "$SRV" in http://*)
            if [ -s "$PEM" ] && [ -s "$TLSPORT" ] && tls_ok; then
                h=${SRV#http://}; h=${h%%/*}; case "$h" in \[*) h=${h%%]*}]; ;; *) h=${h%%:*} ;; esac
                list="$list https://$h:$(cat "$TLSPORT")"
            fi ;;
        esac
        list="$list $SRV"
    done
    for SRV in $list; do
        CA=""; case "$SRV" in https://*:"$(cat "$TLSPORT" 2>/dev/null)") CA="$PEM" ;; esac
        # which address this went to, as the other agents say (Rollcall shows it, and lists it in its certificate)
        { printf '{"sent_to":%s,' "$(js "$SRV" 200)"; tail -c +2 "$TMP.json"; } > "$TMP.send"
        code=$(post /agent/report "$TMP.send")
        [ "$code" = 000 ] && { log "WARN $SRV didn't answer: $(head -c 200 "$TMP.err" 2>/dev/null)"; continue; }
        break
    done   # CA stays set for the enrolment below, which goes to the same address
    case "$code" in
        200) log "Report sent to $SRV"
             tls_reply
             last=$("$LOGREAD" -t 2>/dev/null | tail -1 | stamp); [ "${last:-0}" -gt 0 ] && [ "$last" != "$(cat "$SINCE" 2>/dev/null)" ] && echo "$last" > "$SINCE" ;;
        202) log "Waiting for approval in the Rollcall dashboard" ;;
        401) log "Not enrolled yet: asking to join"
             printf '{"enrol_key":%s,"hostname":%s,"fqdn":%s,"os":%s,"agent_version":"%s","agent_kind":"sh","os_family":"linux","token":"%s","ips":%s}' \
                 "$(js "$ENROL_KEY")" "$(js "$HOSTNAME" 60)" "$(js "$HOSTNAME" 120)" \
                 "$(sed -n 's/.*"os":\("[^"]*"\).*/\1/p' "$TMP.json")" "$AGENT_VERSION" "$token" \
                 "$(sed -n 's/.*"ips":\(\[[^]]*\]\).*/\1/p' "$TMP.json")" > "$TMP.enrol"
             code=$(post /agent/enrol "$TMP.enrol")
             case "$code" in
                 403) log "The add-on rejected the enrolment key. Download a fresh copy of the script from the dashboard." ;;
                 410) log "This router was rejected or revoked in the dashboard. To ask again, run --uninstall then --install." ;;
                 *) log "Waiting for an admin to approve this router in the Rollcall dashboard (HTTP $code)" ;;
             esac ;;
        000) log "ERROR Couldn't reach Rollcall at $SERVER" ;;
        *) log "ERROR Report rejected (HTTP $code)" ;;
    esac
    rm -f "$TMP".*
}

install() {
    mkdir -p -m 700 "$DIR" && chmod 700 "$DIR" && cat "$0" > "$DIR/agent.sh.new" && chmod 700 "$DIR/agent.sh.new" \
        && mv "$DIR/agent.sh.new" "$DIR/agent.sh" || { echo "Couldn't copy to $DIR"; exit 1; }   # private from the start
    grep -q rollcall/agent.sh "$CRON" 2>/dev/null || echo "*/5 * * * * sh $DIR/agent.sh" >> "$CRON"
    grep -qx "$DIR/" /etc/sysupgrade.conf 2>/dev/null || echo "$DIR/" >> /etc/sysupgrade.conf 2>/dev/null
    [ -x /etc/init.d/cron ] && { /etc/init.d/cron enable; /etc/init.d/cron restart; } >/dev/null 2>&1
    echo "Installed in $DIR: it reports every 5 minutes. Sending the first report now..."
    sh "$DIR/agent.sh"; tail -1 "$LOG"
}

uninstall() {
    [ -f "$CRON" ] && sed -i '/rollcall\/agent\.sh/d' "$CRON"
    [ -f /etc/sysupgrade.conf ] && sed -i "\#^$DIR/\$#d" /etc/sysupgrade.conf
    [ -x /etc/init.d/cron ] && /etc/init.d/cron restart >/dev/null 2>&1
    rm -rf "$DIR"; echo "Removed. Remove the router in the Rollcall dashboard too if it's gone for good."
}

# One run at a time: cron starts one every 5 minutes, and a run stuck on something (a ubus call that never
# answers) mustn't let others pile up until the router runs out of memory. A run older than 10 minutes
# is stuck: it's stopped and this one carries on.
take_lock() {
    if mkdir "$LOCK" 2>/dev/null; then echo $$ > "$LOCK/pid"; return 0; fi
    pid=$(cat "$LOCK/pid" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && grep -q rollcall "/proc/$pid/cmdline" 2>/dev/null; then
        age=$(( $(date +%s) - $(date -r "$LOCK/pid" +%s 2>/dev/null || date +%s) ))
        [ "$age" -lt 600 ] && { log "Another run is still going; skipped this one"; return 1; }
        log "WARN stopped a run stuck for $((age / 60)) min"; kill -9 "$pid" 2>/dev/null
    fi
    echo $$ > "$LOCK/pid"; return 0
}

trap 'rm -rf "$TMPD"; [ "$(cat "$LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$LOCK"' EXIT
[ -f "$DIR/since" ] && rm -f "$DIR/since"   # 1.0.0 kept this on flash and wrote it every run
case "$1" in
    --install) install ;;
    --uninstall) uninstall ;;
    --report) build_report; echo ;;
    "") take_lock && send ;;
    *) sed -n '2,15p' "$0"; exit 1 ;;
esac
