#!/usr/bin/env bash
set -euo pipefail
umask 0077

# Install from a fresh checkout on Ubuntu 24.04 amd64.
test "$(id -u)" -eq 0 || { echo 'Run with sudo.' >&2; exit 2; }
ip=${1:?Usage: sudo bash deployment/install-ubuntu.sh <server-IPv4>}
[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo 'An IPv4 address is required.' >&2; exit 2; }
IFS=. read -r a b c d <<< "$ip"
for octet in "$a" "$b" "$c" "$d"; do (( 10#$octet <= 255 )) || { echo 'Invalid IPv4 address.' >&2; exit 2; }; done
grep -q '^ID=ubuntu$' /etc/os-release && grep -q '^VERSION_ID="24.04"$' /etc/os-release || { echo 'Ubuntu 24.04 is required.' >&2; exit 2; }
test "$(uname -m)" = x86_64 || { echo 'amd64 is required.' >&2; exit 2; }
ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$ip" || { echo 'IP is not assigned to this server.' >&2; exit 2; }
for command in curl openssl systemctl runuser python3 ip useradd install; do command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 2; }; done

source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
go=/opt/sharefolder-toolchain/go/bin/go
test -x "$go" && test "$("$go" version)" = 'go version go1.27.1 linux/amd64' || { echo 'Install the pinned Go toolchain from README.md first.' >&2; exit 2; }
test -f "$source_dir/go.mod" && test -f "$source_dir/go.sum" || { echo 'Run from a complete clone.' >&2; exit 2; }
release_version=0.1.5
root=/opt/sharefolder
release="$root/releases/$release_version"
build_dir=$(mktemp -d /tmp/sharefolder-build.XXXXXX)
[[ "$build_dir" == /tmp/sharefolder-build.* ]] || exit 2
trap 'rm -rf -- "$build_dir"' EXIT

cd "$source_dir"
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64
"$go" mod download all
"$go" test -mod=readonly ./...
"$go" build -mod=readonly -trimpath -o "$build_dir/sharefolder" ./cmd/sharefolder
test "$("$build_dir/sharefolder" version | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')" = "$release_version"

if systemctl is-active --quiet sharefolder; then
  test "$(readlink "$root/current")" = "releases/$release_version" && cmp -s "$release/sharefolder" "$build_dir/sharefolder" || { echo 'Service is active with another build; stop it before upgrading.' >&2; exit 3; }
  echo 'ShareFolder is already installed and active.'
  exit 0
fi

if ! id sharefolder >/dev/null 2>&1; then useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin sharefolder; fi
install -d -m 0755 -o root -g root "$root" "$root/releases"
install -d -m 0750 -o root -g sharefolder "$root/config"
install -d -m 0700 -o sharefolder -g sharefolder "$root/config/tls" "$root/state" "$root/data" "$root/data/blobs" "$root/data/staging"
if test -e "$release"; then
  test ! -L "$release" && cmp -s "$release/sharefolder" "$build_dir/sharefolder" || { echo 'Existing release differs; use a new version.' >&2; exit 3; }
else
  install -d -m 0755 -o root -g root "$release"
  install -m 0755 -o root -g root "$build_dir/sharefolder" "$release/sharefolder"
fi

cert="$root/config/tls/server.crt"
key="$root/config/tls/server.key"
if ! test -e "$cert" && ! test -e "$key"; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -subj "/CN=ShareFolder $ip" -addext "subjectAltName=IP:$ip" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$key" -out "$cert" >/dev/null 2>&1
  chown sharefolder:sharefolder "$cert" "$key"
  chmod 0644 "$cert"
  chmod 0600 "$key"
fi
test -f "$cert" && test -f "$key" || { echo 'TLS certificate/key pair is incomplete.' >&2; exit 3; }

env_file="$root/config/sharefolder.env"
if ! test -f "$env_file"; then
  cat > "$env_file" <<EOF
APP_ENV=production
RF_LISTEN=$ip:443
RF_PUBLIC_ORIGIN=https://$ip
RF_METADATA_DIR=$root/state
RF_DATA_DIR=$root/data
RF_TLS_CERT_FILE=$cert
RF_TLS_KEY_FILE=$key
EOF
  chown root:sharefolder "$env_file"
  chmod 0640 "$env_file"
fi
grep -Fxq "RF_LISTEN=$ip:443" "$env_file" && grep -Fxq "RF_PUBLIC_ORIGIN=https://$ip" "$env_file" || { echo 'Existing configuration uses another IP.' >&2; exit 3; }
if test -e "$root/current" && ! test -L "$root/current"; then echo 'current must be a symlink.' >&2; exit 3; fi
ln -sfn "releases/$release_version" "$root/current"

run_app() { runuser -u sharefolder -- "$root/current/sharefolder" --env-file "$env_file" "$@"; }
run_app doctor
run_app migrate
if run_app admin-status | grep -q '"admin_exists":false'; then
  printf '%s' admin | run_app bootstrap-admin --username admin --display-name Administrator --password-stdin
fi
install -m 0644 -o root -g root "$source_dir/deployment/sharefolder-github.service" /etc/systemd/system/sharefolder.service
systemctl daemon-reload
systemctl enable --now sharefolder.service
ready=false
for attempt in $(seq 1 30); do
  if curl --connect-timeout 3 --max-time 5 --fail --silent --show-error --cacert "$cert" "https://$ip/health/ready"; then ready=true; break; fi
  sleep 1
done
test "$ready" = true || { echo 'Service did not become ready.' >&2; exit 3; }
echo
echo "Ready at https://$ip — initial login: admin / admin"
