#!/bin/bash
# The checks themselves. Runs inside the container started by install-test.sh;
# PKG_FORMAT is "deb" or "rpm".
#
# NOTE: deliberately no `set -o pipefail`. Several checks are of the form
#   cmd | grep -q pattern
# and `grep -q` exits the moment it matches, which can SIGPIPE the writer. With
# pipefail that races into a spurious failure — it did, on Rocky but not Debian,
# which is exactly how long a flaky check can hide. The maintainer scripts under
# test use `set -e` without pipefail for the same reason.
set -u

PASS=0; FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
step() { echo; echo "=== $* ==="; }

case "${PKG_FORMAT:-deb}" in
    deb)
        PKG=$(ls /pkg/*.deb | head -1)
        install_pkg()   { dpkg -i "$PKG"; }
        reinstall_pkg() { dpkg -i "$PKG" >/dev/null 2>&1; }
        remove_pkg()    { dpkg -r edr-agent; }
        purge_pkg()     { dpkg -P edr-agent >/dev/null 2>&1; }
        SUPPORTS_PURGE=1
        ;;
    rpm)
        PKG=$(ls /pkg/*.rpm | head -1)
        install_pkg()   { rpm -i --nodeps "$PKG"; }
        reinstall_pkg() { rpm -i --nodeps --replacepkgs "$PKG" >/dev/null 2>&1; }
        remove_pkg()    { rpm -e --nodeps edr-agent; }
        purge_pkg()     { rpm -e --nodeps edr-agent >/dev/null 2>&1; }
        SUPPORTS_PURGE=0
        ;;
    *) echo "unknown PKG_FORMAT" >&2; exit 2 ;;
esac
echo "package: $PKG"

step "1. install"
install_pkg && ok "install succeeded" || bad "install failed"

step "2. payload"
for f in /usr/local/bin/edr-agent /usr/local/bin/edr-watchdog \
         /lib/systemd/system/edr-watchdog.service /etc/edr/agent.toml; do
  [ -e "$f" ] && ok "present: $f" || bad "missing: $f"
done
[ -x /usr/local/bin/edr-agent ] && ok "agent is executable" || bad "agent not executable"

step "3. service account"
getent passwd edr >/dev/null && ok "user 'edr' created"  || bad "user 'edr' missing"
getent group  edr >/dev/null && ok "group 'edr' created" || bad "group 'edr' missing"

step "4. first-run config (no SERVER_URL provided)"
# The agent id must be generated; the URL must stay empty, because an agent
# pointed at nothing runs happily while connecting to nothing — the failure
# mode most easily mistaken for a working install.
grep -qE '^id[[:space:]]*=[[:space:]]*"[0-9a-f-]{36}"' /etc/edr/agent.toml \
  && ok "agent id generated" || bad "agent id not generated"
grep -qE '^url[[:space:]]*=[[:space:]]*""' /etc/edr/agent.toml \
  && ok "server url left empty (service must stay stopped)" \
  || bad "server url unexpectedly set"
ID_BEFORE=$(grep -E '^id' /etc/edr/agent.toml)

step "5. the binary runs, and advertises the flag preremove probes for"
/usr/local/bin/edr-agent -version && ok "-version works" || bad "-version failed"
HELP=$(/usr/local/bin/edr-agent -help 2>&1 || true)
case "$HELP" in
  *-verify-uninstall*) ok "-verify-uninstall advertised" ;;
  *)                   bad "-verify-uninstall missing" ;;
esac

step "6. upgrade must not regenerate the agent id"
reinstall_pkg
ID_AFTER=$(grep -E '^id' /etc/edr/agent.toml)
[ "$ID_BEFORE" = "$ID_AFTER" ] \
  && ok "agent id preserved across reinstall (dashboard identity kept)" \
  || bad "agent id changed on upgrade: $ID_BEFORE -> $ID_AFTER"

step "7. remove with NO uninstall guard → allowed, state preserved"
remove_pkg && ok "removal allowed when unprotected" || bad "removal blocked with no guard"
[ ! -e /usr/local/bin/edr-agent ] && ok "binaries removed" || bad "binaries still present"
# Regression guard: these directories are created by postinstall, NOT shipped as
# package content. Shipping them made the package manager their owner, and it
# deleted them on removal while postremove claimed they were kept.
[ -d /var/log/edr ] && ok "logs kept (forensic material)" || bad "logs removed on plain remove"
[ -d /var/lib/edr ] && ok "data kept (forensic material)" || bad "data removed on plain remove"

step "8. reinstall and plant an uninstall guard"
reinstall_pkg
# Guard for the password below. iterations=1000 keeps the test fast; Verify
# honours the count stored in the file, so this exercises the real code path.
python3 - <<'PY'
import hashlib, base64, json
salt = b"0123456789abcdef"
digest = hashlib.pbkdf2_hmac("sha256", b"correct horse battery staple", salt, 1000, 32)
json.dump({"version": 1, "algorithm": "pbkdf2-hmac-sha256", "iterations": 1000,
           "salt": base64.b64encode(salt).decode(),
           "digest": base64.b64encode(digest).decode(),
           "updated_at": "2026-08-10T00:00:00Z"},
          open("/etc/edr/uninstall.guard", "w"), indent=2)
PY
chmod 600 /etc/edr/uninstall.guard
ok "guard planted"

step "9. remove WITHOUT the password → must be refused"
# This is the point of the whole exercise: enforcing the password only in
# uninstall.sh would leave `apt remove` / `rpm -e` as the way around it, and on
# a fleet managed by a package manager that is the normal removal path.
if remove_pkg >/tmp/rm1.log 2>&1; then
  bad "removal succeeded without the password — protection bypassed"
else
  ok "removal refused"
fi
[ -x /usr/local/bin/edr-agent ] && ok "agent still installed after refusal" || bad "agent removed despite refusal"

step "10. remove with a WRONG password → must be refused"
if EDR_UNINSTALL_PASSWORD=wrong-password remove_pkg >/tmp/rm2.log 2>&1; then
  bad "removal succeeded with a wrong password"
else
  ok "removal refused with a wrong password"
fi
[ -x /usr/local/bin/edr-agent ] && ok "agent still installed" || bad "agent removed despite refusal"

step "11. remove with the CORRECT password → allowed"
if EDR_UNINSTALL_PASSWORD='correct horse battery staple' remove_pkg >/tmp/rm3.log 2>&1; then
  ok "removal allowed with the correct password"
else
  bad "removal refused with the correct password:"; tail -5 /tmp/rm3.log
fi
[ ! -e /usr/local/bin/edr-agent ] && ok "binaries removed" || bad "binaries still present"

if [ "$SUPPORTS_PURGE" = "1" ]; then
  step "12. purge removes what it says it removes"
  reinstall_pkg
  rm -f /etc/edr/uninstall.guard
  purge_pkg
  [ ! -d /etc/edr ] && ok "purge removed /etc/edr" || bad "purge left /etc/edr"
fi

echo
echo "==================== ${PKG_FORMAT}: ${PASS} passed, ${FAIL} failed ===================="
[ "$FAIL" -eq 0 ]
