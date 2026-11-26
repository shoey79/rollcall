#!/bin/sh
# Rollcall agent for pfSense, OPNsense and FreeBSD: a shell script, so nothing needs installing (curl, which
# pfSense and OPNsense have, sends the report).
#
# Reports to the Rollcall add-on every 5 minutes (cron): uptime, CPU, memory, load, temperatures, disks and ZFS
# pools, network interfaces with their traffic and errors, and on a firewall: gateways (up or down, delay, loss),
# CARP (master or backup), IPsec and OpenVPN tunnels, the pf state table, and whether a pfSense update is waiting
# (checked once a day). Read only: it never changes the firewall's settings.
#
#   sh rollcall-agent-freebsd.sh --install     copy to /usr/local/etc/rollcall and run every 5 minutes
#   sh rollcall-agent-freebsd.sh --uninstall   remove it again
#   sh rollcall-agent-freebsd.sh --report      print the report instead of sending it
#   sh rollcall-agent-freebsd.sh               send one report now
#
# The first report asks to join; approve it in the Rollcall dashboard (Manage > Agents).
# Downloaded from the dashboard, the add-on's address and enrolment key are already filled in.

AGENT_VERSION="1.0.0"
SERVER="__PM_SERVER__"
ENROL_KEY="__PM_ENROL_KEY__"
IGNORE_CERT=0
# Rollcall's own HTTPS certificate authority, built in when the script is downloaded with HTTPS on. Only this is
# trusted; a certificate in a reply never replaces it.
TLS_CA='__PM_TLS_CA__'
umask 077   # everything this agent writes (its token, the report it sends) is root's only

R="${RC_ROOT:-}"   # tests only: a folder standing in for / (the system's files under it)
DIR="${RC_DIR:-/usr/local/etc/rollcall}"   # under /usr/local: kept through pfSense and OPNsense upgrades
STATE="$DIR/token"
PEM="$DIR/rollcall.pem"; TLSPORT="$DIR/tls_port"
UPDCHECK="$DIR/update_check"     # the daily update check's answer (it takes several seconds)
LOG="${RC_LOG:-/var/log/rollcall-agent.log}"
[ -L "$LOG" ] && rm -f "$LOG"
RUN="${RC_RUN:-/var/run}"
LOCK="$RUN/rollcall.lock"
CROND="${RC_CROND:-/usr/local/etc/cron.d}"   # FreeBSD's cron reads it; pfSense doesn't rewrite it (it does /etc/crontab)
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/rollcall.XXXXXX" 2>/dev/null) || { TMPD="${TMPDIR:-/tmp}/rollcall.$$"; rm -rf "$TMPD"; mkdir -m 700 "$TMPD" || exit 1; }
TMP="$TMPD/r"
ERRORS=""
PATH="$PATH:/usr/local/bin:/usr/local/sbin:/sbin:/usr/sbin"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; [ -t 1 ] && echo "$*"
    [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 262144 ] && tail -c 131072 "$LOG" | sed 1d > "$LOG.new" && mv "$LOG.new" "$LOG"
    return 0
}
err() { ERRORS="$ERRORS${ERRORS:+,}$(js "$1")"; }
have() { command -v "$1" >/dev/null 2>&1; }
js() {
    printf '%s' "$1" | head -c "${2:-240}" | tr -d '\000-\010\013\014\016-\037' |
        sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r//g' | awk 'BEGIN{ORS=""} {if (NR>1) print "\\n"; print}' |
        { printf '"'; cat; printf '"'; }
}
join() { awk 'BEGIN{ORS=""} NR>1{print ","} {print}'; }
jl() { js "$@"; echo; }
num() { case "$1" in ''|*[!0-9.-]*) echo null ;; *) echo "$1" ;; esac; }
utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
sc() { sysctl -n "$1" 2>/dev/null; }

# --- what this is: pfSense, OPNsense or FreeBSD ------------------------------------------------------------
PRODUCT=FreeBSD
if [ -f "$R/etc/platform" ] && grep -qi pfsense "$R/etc/platform" 2>/dev/null; then PRODUCT=pfSense
elif have opnsense-version; then PRODUCT=OPNsense; fi
product_version() {
    case "$PRODUCT" in
        pfSense) head -1 "$R/etc/version" 2>/dev/null ;;
        OPNsense) opnsense-version -v 2>/dev/null ;;
        *) freebsd-version 2>/dev/null || uname -r ;;
    esac
}

system_info() {
    HOSTNAME=$(hostname -s 2>/dev/null || hostname)
    fq=$(hostname 2>/dev/null)
    pv=$(product_version); bsd=$(freebsd-version 2>/dev/null || uname -r)
    os="$PRODUCT"; [ "$PRODUCT" != FreeBSD ] && os="$PRODUCT $pv (FreeBSD $bsd)"; [ "$PRODUCT" = FreeBSD ] && os="FreeBSD $bsd"
    model=$(sc hw.model)
    vm=$(sc kern.vm_guest); case "$vm" in ''|none) virt=false ;; *) virt=true ;; esac
    boot=$(sc kern.boottime | sed -n 's/^{ *sec = \([0-9]*\).*/\1/p')   # "{ sec = 1764000000, usec = 123 } ..."
    now=$(date +%s); up=$(( now - ${boot:-$now} ))
    bootiso=$(date -u -r "${boot:-$now}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || utc)
    ps=$(sc hw.pagesize); ps=${ps:-4096}
    mt=$(( $(sc hw.physmem || echo 0) / 1048576 ))
    fr=$(( ( $(sc vm.stats.vm.v_free_count || echo 0) + $(sc vm.stats.vm.v_inactive_count || echo 0) + $(sc vm.stats.vm.v_cache_count || echo 0) ) * ps / 1048576 ))
    set -- $(sc vm.loadavg | tr -d '{}')
    load="[$(num "$1"),$(num "$2"),$(num "$3")]"
    cores=$(sc hw.ncpu)
    # CPU use over a second, from two readings of kern.cp_time (user nice sys intr idle)
    c1=$(sc kern.cp_time); sleep 1; c2=$(sc kern.cp_time)
    cpu=$(echo "$c1 $c2" | awk '{t=($6+$7+$8+$9+$10)-($1+$2+$3+$4+$5); i=$10-$5; if (t>0) printf "%.1f", 100*(t-i)/t; else print "null"}')
    ips=$(ifconfig -a inet 2>/dev/null | awk '$1=="inet" && $2!~/^127\./ {print $2}')
    ipj=$(for i in $ips; do jl "$i"; done | head -8 | join)
    printf '"hostname":%s,"fqdn":%s,"os":%s,"os_build":%s,"os_id":%s,"os_version_id":%s,"hw_model":%s,"hw_vendor":"","virtual":%s,' \
        "$(js "$HOSTNAME" 60)" "$(js "$fq" 120)" "$(js "$os" 120)" "$(js "$bsd" 60)" "$(js "$(echo "$PRODUCT" | tr 'A-Z' 'a-z')" 30)" "$(js "$pv" 30)" "$(js "$model" 80)" "$virt"
    printf '"boot_time":"%s","uptime_s":%s,"mem_total_mb":%s,"mem_free_mb":%s,"load":%s,"cpu_cores":%s,"cpu_pct":%s,"ips":[%s],' \
        "$bootiso" "$(num "$up")" "$(num "$mt")" "$(num "$fr")" "$load" "$(num "$cores")" "$cpu" "$ipj"
    printf '"domain":"","part_of_domain":false,"workstation":false,"pending_reboot":false,"updates_pending":null,"security_updates":null,'
}

# --- disks: UFS file systems, and ZFS pools as a whole (their datasets share the pool's space) ---------------
disks() {
    { df -kP -t ufs 2>/dev/null | awk 'NR>1 && $2>0 {print $6, $2, $4, $1}' | while read -r mnt size free dev; do
        printf '{"name":%s,"label":%s,"size_gb":%s,"free_gb":%s}\n' "$(js "$mnt")" "$(js "$dev" 80)" \
            "$(awk "BEGIN{printf \"%.3f\", $size/1048576}")" "$(awk "BEGIN{printf \"%.3f\", $free/1048576}")"
      done
      have zpool && zpool list -Hp -o name,size,free 2>/dev/null | while read -r n size free; do
        printf '{"name":%s,"label":"ZFS pool","size_gb":%s,"free_gb":%s}\n' "$(js "zpool $n")" \
            "$(awk "BEGIN{printf \"%.3f\", $size/1073741824}")" "$(awk "BEGIN{printf \"%.3f\", $free/1073741824}")"
      done; } | head -20 | join
}
zpools() {
    have zpool || return 0
    zpool list -H -o name,health 2>/dev/null | while read -r n h; do
        printf '{"name":%s,"layout":"zfs","health":%s,"status":%s}\n' "$(js "zpool $n")" "$(js "$h" 20)" "$(js "$h" 20)"
    done | join
}

# --- interfaces: state, speed and the counters from netstat -ibn's <Link#> rows -------------------------------
nics() {
    # pfSense: each interface's own name for it (LAN, WAN or the description set in the GUI)
    if [ "$PRODUCT" = pfSense ] && have php; then
        php -r 'require_once("config.inc"); foreach (get_configured_interface_with_descr() as $k => $v) echo get_real_interface($k) . "|" . $v . "\n";' 2>/dev/null > "$TMP.desc"
    fi
    netstat -ibn 2>/dev/null | awk '$3 ~ /^<Link#/ {n=$1; if (NF>=12) print n, $5, $6, $7, $8, $9, $10, $11; else print n, $4, $5, $6, $7, $8, $9, $10}' > "$TMP.ns"
    for n in $(ifconfig -l 2>/dev/null); do
        case "$n" in lo*|pflog*|pfsync*|enc*|gif*|stf*|ipfw*|usbus*) continue ;; esac
        i=$(ifconfig "$n" 2>/dev/null) || continue
        st=down
        echo "$i" | head -1 | grep -q '<UP' || st=disabled
        if [ "$st" != disabled ]; then
            s=$(echo "$i" | sed -n 's/^[[:space:]]*status: //p' | head -1)
            case "$s" in active|associated|running|"") st=up ;; esac
            [ "$s" = "no carrier" ] && st=down
        fi
        # "media: Ethernet autoselect (1000baseT <full-duplex>)" or "(10Gbase-T ...)": Mbit/s
        speed=$(echo "$i" | awk '/media:/ { if (match($0, /\([0-9]+G?base/)) { s = substr($0, RSTART + 1, RLENGTH - 5); g = (s ~ /G$/); sub(/G$/, "", s); print (g ? s * 1000 : s + 0); exit } }')
        [ "$st" = up ] || speed=0
        mac=$(echo "$i" | awk '$1=="ether"{print $2; exit}')
        desc=$(grep "^$n|" "$TMP.desc" 2>/dev/null | head -1 | cut -d'|' -f2)
        ipj=$(echo "$i" | awk '$1=="inet"{print $2}' | while read -r a; do jl "$a"; done | head -8 | join)
        set -- $(awk -v n="$n" '$1==n{print $2, $3, $4, $5, $6, $7, $8; exit}' "$TMP.ns")
        virt=true; case "$n" in em*|igb*|ix*|ixl*|igc*|re*|bge*|vtnet*|hn*|vmx*|cxl*|mlx*|bnxt*|ice*|ax*|ue*) virt=false ;; esac
        printf '{"name":%s,"desc":%s,"status":"%s","speed_mbps":%s,"mac":%s,"virtual":%s,"media":"","ips":[%s]' \
            "$(js "$n" 40)" "$(js "$desc" 120)" "$st" "${speed:-0}" "$(js "$mac" 40)" "$virt" "$ipj"
        [ $# -ge 7 ] && printf ',"rx_errors":%s,"rx_drops":%s,"rx_bytes":%s,"tx_errors":%s,"tx_bytes":%s' "$(num "$2")" "$(num "$3")" "$(num "$4")" "$(num "$6")" "$(num "$7")"
        printf '}\n'
    done | head -40 | join
}

# --- firewall: gateways, CARP, IPsec, OpenVPN, pf states, updates ------------------------------------------
gateways() {
    if [ "$PRODUCT" = pfSense ] && have php; then
        # pfSense's own view (dpinger): name, monitor IP, delay, deviation, loss and status for each gateway
        php -r 'require_once("gwlb.inc"); foreach (return_gateways_status(true) as $g) echo $g["name"] . "|" . $g["monitorip"] . "|" . $g["delay"] . "|" . $g["stddev"] . "|" . $g["loss"] . "|" . $g["status"] . "|" . $g["substatus"] . "\n";' 2>/dev/null
    elif [ -x "$R/usr/local/opnsense/scripts/routes/gateway_status.php" ]; then
        "$R/usr/local/opnsense/scripts/routes/gateway_status.php" 2>/dev/null | tr '{' '\n' | sed -n 's/.*"name":"\([^"]*\)".*"address":"\([^"]*\)".*"status":"\([^"]*\)".*"loss":"\([^"]*\)".*"stddev":"\([^"]*\)".*"delay":"\([^"]*\)".*/\1|\2|\6|\5|\4|\3|/p'
    fi | head -32 | while IFS='|' read -r n mon d sd l s sub; do
        [ -n "$n" ] || continue
        printf '{"name":%s,"monitor":%s,"delay_ms":%s,"stddev_ms":%s,"loss_pct":%s,"status":%s,"substatus":%s}\n' "$(js "$n" 60)" "$(js "$mon" 60)" \
            "$(num "$(echo "$d" | tr -dc '0-9.')")" "$(num "$(echo "$sd" | tr -dc '0-9.')")" "$(num "$(echo "$l" | tr -dc '0-9.')")" "$(js "$s" 20)" "$(js "$sub" 20)"
    done | join
}
carp() {
    ifconfig 2>/dev/null | awk '/^[a-z]/{i=$1; sub(/:$/,"",i)} $1=="carp:"{print i, $2, $4}' | head -32 | while read -r i st vhid; do
        printf '{"interface":%s,"state":%s,"vhid":%s}\n' "$(js "$i" 40)" "$(js "$st" 20)" "$(num "$vhid")"
    done | join
}
ipsec() {
    have swanctl || return 0
    swanctl --list-conns 2>/dev/null > "$TMP.conns" || return 0
    swanctl --list-sas 2>/dev/null > "$TMP.sas"
    # configured connections (a remote of %any is for mobile clients: not expected to be up), and which are up
    conns=$(awk '/^[^ \t].*: IKEv[12]/{if (n != "") print n, m; n=$1; sub(/:$/,"",n); m=0; next}
                 n != "" && $1 == "remote:" && $2 == "%any" {m=1}
                 END {if (n != "") print n, m}' "$TMP.conns")
    up=$(awk '/^[^ \t].*: #[0-9]+, ESTABLISHED/{n=$1; sub(/:$/,"",n); print n}' "$TMP.sas" | sort -u)
    total=0; mobile=0; down=""
    for c in $(echo "$conns" | awk '{print $1":"$2}'); do
        n=${c%:*}; m=${c##*:}; total=$((total + 1))
        if [ "$m" = 1 ]; then mobile=$((mobile + 1)); continue; fi
        echo "$up" | grep -qx "$n" || down="$down${down:+
}$n"
    done
    printf '{"configured":%s,"mobile":%s,"up":%s,"down":[%s]}' "$total" "$mobile" "$(echo "$up" | grep -c .)" \
        "$(echo "$down" | grep . | head -20 | while read -r d; do jl "$d" 60; done | join)"
}
openvpn() {
    for s in "$R"/var/etc/openvpn/*/sock; do
        [ -S "$s" ] || continue
        n=$(basename "$(dirname "$s")")
        case "$n" in
            client*) st=$(printf 'state\nquit\n' | nc -U -w 2 "$s" 2>/dev/null | grep -m1 '^[0-9]*,' | cut -d, -f2)
                     printf '{"name":%s,"kind":"client","state":%s}\n' "$(js "$n" 40)" "$(js "${st:-unknown}" 20)" ;;
            server*) cl=$(printf 'status 2\nquit\n' | nc -U -w 2 "$s" 2>/dev/null | grep -c '^CLIENT_LIST,')
                     printf '{"name":%s,"kind":"server","clients":%s}\n' "$(js "$n" 40)" "$(num "$cl")" ;;
        esac
    done | head -32 | join
}
pfstates() {
    have pfctl || return 0
    cur=$(pfctl -si 2>/dev/null | awk '/current entries/{print $3; exit}')
    lim=$(pfctl -sm 2>/dev/null | awk '$1=="states"{print $NF; exit}')
    [ -n "$cur" ] && printf '{"current":%s,"limit":%s}' "$(num "$cur")" "$(num "$lim")"
}
temps() {
    sysctl -a 2>/dev/null | sed -n 's/^\(dev\.cpu\.[0-9]*\.temperature\|hw\.acpi\.thermal\.tz[0-9]*\.temperature\): \([0-9.]*\)C$/\1 \2/p' | head -16 |
        while read -r k v; do printf '{"name":%s,"celsius":%s}\n' "$(js "$k" 60)" "$(num "$v")"; done | join
}
# pfSense's own update check, once a day (it takes several seconds): "up to date", or the version waiting
updates() {
    [ "$PRODUCT" = pfSense ] && have pfSense-upgrade || return 0
    now=$(date +%s); last=$(head -1 "$UPDCHECK" 2>/dev/null | cut -d' ' -f1)
    if [ -z "$last" ] || [ $((now - ${last:-0})) -gt 86400 ]; then
        out=$(pfSense-upgrade -c 2>&1 | tail -5)
        if echo "$out" | grep -qi 'up to date'; then a=no
        elif v=$(echo "$out" | grep -io 'version [0-9][0-9a-z._-]* is available' | head -1); [ -n "$v" ]; then a="yes $(echo "$v" | awk '{print $2}')"
        else a="unknown"; fi
        mkdir -p "$DIR"; echo "$now $a" > "$UPDCHECK"
    fi
    set -- $(head -1 "$UPDCHECK")
    printf '{"checked":"%s","available":%s,"version":%s}' "$(date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" \
        "$(case "$2" in yes) echo true ;; no) echo false ;; *) echo null ;; esac)" "$(js "$3" 30)"
}

build_report() {
    started=$(date +%s)
    printf '{"agent_version":"%s","agent_kind":"sh","os_family":"linux","platform":"freebsd","ps_version":%s,"collected":"%s","tls_capable":true,' \
        "$AGENT_VERSION" "$(js "sh ($PRODUCT)" 60)" "$(utc)"
    system_info || err "system info failed"
    printf '"disks":[%s],' "$(disks)"
    printf '"services":{"watched":[],"stopped_auto":[]},'
    roles="\"Firewall ($PRODUCT)\""; [ "$PRODUCT" = FreeBSD ] && roles="\"FreeBSD\""
    printf '"roles":[%s],"events":{"counts":{},"recent":[]},"sessions":[],' "$roles"
    printf '"security":{"failed_logons":{"count":0,"top":[]},"items":[],"admins":[]},'
    n=$(nics) || err "network interfaces failed"
    z=$(zpools)
    fw=""
    if [ "$PRODUCT" != FreeBSD ]; then
        g=$(gateways) || err "gateways failed"
        fw="\"product\":$(js "$PRODUCT"),\"version\":$(js "$(product_version)" 40),\"gateways\":[$g],\"carp\":[$(carp)],\"openvpn\":[$(openvpn)]"
        i=$(ipsec); [ -n "$i" ] && fw="$fw,\"ipsec\":$i"
        p=$(pfstates); [ -n "$p" ] && fw="$fw,\"states\":$p"
        u=$(updates); [ -n "$u" ] && fw="$fw,\"update\":$u"
    fi
    t=$(temps)
    c=""
    [ -n "$n" ] && c="\"nics\":{\"adapters\":[$n]}"
    [ -n "$z" ] && c="$c${c:+,}\"storage\":{\"physical\":[],\"virtual\":[$z],\"volumes\":[],\"warnings\":[],\"hardware\":[]}"
    [ -n "$fw" ] && c="$c${c:+,}\"firewall\":{$fw}"
    c="$c${c:+,}\"temps\":{\"sensors\":[$t],\"virtual\":$( [ "$(sc kern.vm_guest)" != none ] && [ -n "$(sc kern.vm_guest)" ] && echo true || echo false)}"
    printf '"checks":{%s},' "$c"
    printf '"errors":[%s],"run_ms":%s}' "$ERRORS" "$(( ($(date +%s) - started) * 1000 ))"
}

# --- talking to Rollcall (curl: pfSense and OPNsense have it; on FreeBSD, pkg install curl) -----------------
post() {
    url="$SRV$1"; rm -f "$TMP.reply"
    have curl || { echo 000; return; }
    set -- -sS -o "$TMP.reply" -w '%{http_code}' -m 30 -H 'Content-Type: application/json' --data-binary "@$2"
    [ "$IGNORE_CERT" = 1 ] && set -- "$@" -k
    [ -n "$CA" ] && set -- "$@" --cacert "$CA"
    code=$(curl "$@" "$url" 2>"$TMP.err"); echo "${code:-000}" | tail -c 4 | head -c 3; echo
}
tls_builtin() {
    case "$TLS_CA" in *"BEGIN CERTIFICATE"*) ;; *) return 1 ;; esac
    mkdir -p "$DIR"
    printf '%s\n' "$TLS_CA" > "$TMP.ca"
    cmp -s "$TMP.ca" "$PEM" || { cp "$TMP.ca" "$PEM"; chmod 600 "$PEM"; }
}
# The reply only says which port Rollcall's HTTPS is on (and, for a copy without the authority built in, its
# certificate, trusted once and never replaced). Nothing in a reply turns HTTPS off.
tls_reply() {
    port=$(sed -n 's/.*"tls":{[^}]*"port":\([0-9]*\).*/\1/p' "$TMP.reply" 2>/dev/null | head -1)
    case "$port" in ''|*[!0-9]*) return 0 ;; esac
    if [ ! -s "$PEM" ]; then
        sed -n 's/.*"tls_cert":"\([^"]*\)".*/\1/p' "$TMP.reply" | sed 's/\\n/\
/g' > "$TMP.pem"
        grep -q 'BEGIN CERTIFICATE' "$TMP.pem" || return 0
        cp "$TMP.pem" "$PEM"; chmod 600 "$PEM"
        log "Rollcall's HTTPS is on: reports go to port $port from the next run"
    fi
    [ "$(cat "$TLSPORT" 2>/dev/null)" = "$port" ] || echo "$port" > "$TLSPORT"
}

send() {
    tls_builtin
    [ -s "$STATE" ] || { mkdir -p "$DIR"; LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c 64 > "$STATE"; chmod 600 "$STATE"; }
    token=$(cat "$STATE")
    build_report > "$TMP.body"
    { printf '{"agent_token":"%s",' "$token"; tail -c +2 "$TMP.body"; } > "$TMP.json"
    list=""
    for SRV in $(echo "$SERVER" | tr ',;' '  '); do
        SRV=${SRV%/}
        case "$SRV" in http://*)
            if [ -s "$PEM" ] && [ -s "$TLSPORT" ]; then
                h=${SRV#http://}; h=${h%%/*}; case "$h" in \[*) h=${h%%]*}]; ;; *) h=${h%%:*} ;; esac
                list="$list https://$h:$(cat "$TLSPORT")"
            fi ;;
        esac
        list="$list $SRV"
    done
    for SRV in $list; do
        CA=""; case "$SRV" in https://*:"$(cat "$TLSPORT" 2>/dev/null)") CA="$PEM" ;; esac
        { printf '{"sent_to":%s,' "$(js "$SRV" 200)"; tail -c +2 "$TMP.json"; } > "$TMP.send"
        code=$(post /agent/report "$TMP.send")
        [ "$code" = 000 ] && { log "WARN $SRV didn't answer: $(head -c 200 "$TMP.err" 2>/dev/null)"; continue; }
        break
    done
    case "$code" in
        200) log "Report sent to $SRV"; tls_reply ;;
        202) log "Waiting for approval in the Rollcall dashboard" ;;
        401) log "Not enrolled yet: asking to join"
             printf '{"enrol_key":%s,"hostname":%s,"fqdn":%s,"os":%s,"agent_version":"%s","agent_kind":"sh","os_family":"linux","token":"%s","ips":%s}' \
                 "$(js "$ENROL_KEY")" "$(js "$HOSTNAME" 60)" "$(js "$HOSTNAME" 120)" \
                 "$(sed -n 's/.*"os":\("[^"]*"\).*/\1/p' "$TMP.json")" "$AGENT_VERSION" "$token" \
                 "$(sed -n 's/.*"ips":\(\[[^]]*\]\).*/\1/p' "$TMP.json")" > "$TMP.enrol"
             code=$(post /agent/enrol "$TMP.enrol")
             case "$code" in
                 403) log "The add-on rejected the enrolment key. Download a fresh copy of the script from the dashboard." ;;
                 410) log "This device was rejected or revoked in the dashboard. To ask again, run --uninstall then --install." ;;
                 *) log "Waiting for an admin to approve this device in the Rollcall dashboard (HTTP $code)" ;;
             esac ;;
        000) log "ERROR Couldn't reach Rollcall at $SERVER$(have curl || echo ' (curl is missing: pkg install curl)')" ;;
        *) log "ERROR Report rejected (HTTP $code)" ;;
    esac
    rm -f "$TMP".*
}

install() {
    mkdir -p "$DIR" && chmod 700 "$DIR" && cat "$0" > "$DIR/agent.sh.new" && chmod 700 "$DIR/agent.sh.new" \
        && mv "$DIR/agent.sh.new" "$DIR/agent.sh" || { echo "Couldn't copy to $DIR"; exit 1; }
    mkdir -p "$CROND" && printf '# Rollcall agent: a report every 5 minutes\n*/5\t*\t*\t*\t*\troot\t/bin/sh %s/agent.sh\n' "$DIR" > "$CROND/rollcall" \
        && chmod 644 "$CROND/rollcall" || { echo "Couldn't add the cron job in $CROND"; exit 1; }
    have curl || echo "Note: curl isn't installed, so reports can't be sent. On FreeBSD: pkg install curl"
    echo "Installed in $DIR: it reports every 5 minutes. Sending the first report now..."
    sh "$DIR/agent.sh"; tail -1 "$LOG"
}

uninstall() {
    rm -f "$CROND/rollcall"
    rm -rf "$DIR"; echo "Removed. Remove the device in the Rollcall dashboard too if it's gone for good."
}

take_lock() {
    if mkdir "$LOCK" 2>/dev/null; then echo $$ > "$LOCK/pid"; return 0; fi
    pid=$(cat "$LOCK/pid" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        age=$(( $(date +%s) - $(stat -f %m "$LOCK/pid" 2>/dev/null || date -r "$LOCK/pid" +%s 2>/dev/null || date +%s) ))
        [ "$age" -lt 600 ] && { log "Another run is still going; skipped this one"; return 1; }
        log "WARN stopped a run stuck for $((age / 60)) min"; kill -9 "$pid" 2>/dev/null
    fi
    echo $$ > "$LOCK/pid"; return 0
}

trap 'rm -rf "$TMPD"; [ "$(cat "$LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$LOCK"' EXIT
case "$1" in
    --install) install ;;
    --uninstall) uninstall ;;
    --report) build_report; echo ;;
    "") take_lock && send ;;
    *) sed -n '2,16p' "$0"; exit 1 ;;
esac
