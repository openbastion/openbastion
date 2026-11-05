#!/usr/bin/env bash
set -euo pipefail

compose_file="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/docker-compose.yml"
max_attempts="${1:-12}"
wait_seconds="${2:-10}"
default_iface="$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')"
bridge_ifaces=()
while read -r iface; do
	bridge_ifaces+=("$iface")
done < <(ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}')
rules=()
rule_added=0

build_rules() {
	local iface
	local rule
	rules=()
	for iface in "${bridge_ifaces[@]}"; do
		rule="-i ${iface} -o ${iface} -m comment --comment openbastion-base44-preview -j ACCEPT"
		rules+=("$rule")
		rule="-i ${iface} -o ${default_iface} -m comment --comment openbastion-base44-preview-egress -j ACCEPT"
		rules+=("$rule")
		rule="-i ${default_iface} -o ${iface} -m comment --comment openbastion-base44-preview-ingress -j ACCEPT"
		rules+=("$rule")
	done
}

rule_exists() {
	local rule
	for rule in "${rules[@]}"; do
		if ! sudo -n iptables-legacy -C FORWARD ${rule} >/dev/null 2>&1; then
			return 1
		fi
	done
	return 0
}

remove_rule() {
	local rule
	for rule in "${rules[@]}"; do
		sudo -n iptables-legacy -D FORWARD ${rule} >/dev/null 2>&1 || true
	done
}

diagnose_web() {
	echo "== Diagnostic conteneur web =="
	docker exec openbastion-web-1 sh -lc '
		printf "== resolv.conf ==\n"; cat /etc/resolv.conf 2>/dev/null || true
		printf "\n== gets hosts ==\n"; getent hosts registry.npmjs.org 2>/dev/null || true
		printf "\n== curl registry ==\n"; curl -I --max-time 15 https://registry.npmjs.org/ 2>&1 || true
		printf "\n== env ==\n"; env | sort | grep -Ei "(http|https|proxy|npm|nvm|node|dns)" || true
	'
	echo "== Remarque =="
	echo "Le symptôme est typique d'un blocage du filtrage Docker/iptables sur le host : la bridge Docker (${bridge_ifaces[*]}) ne peut pas sortir vers ${default_iface}, donc le conteneur ne résout ni npm."
	echo "Les règles temporaires attendues sont :"
	for rule in "${rules[@]}"; do
		echo "sudo -n iptables-legacy -I FORWARD 1 ${rule}"
	done
}

trap 'status=$?; if [[ $status -ne 0 && $rule_added -eq 1 ]]; then remove_rule || true; fi' EXIT

build_rules

if ! rule_exists; then
	for rule in "${rules[@]}"; do
		sudo -n iptables-legacy -I FORWARD 1 ${rule}
	done
	rule_added=1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker n'est pas disponible dans le PATH" >&2
  exit 127
fi

for attempt in $(seq 1 "$max_attempts"); do
  echo "Tentative $attempt/$max_attempts pour démarrer le conteneur web"

  docker compose -f "$compose_file" up -d --no-deps web || true
  sleep "$wait_seconds"

  if docker ps --format '{{.Names}}' | grep -qx 'openbastion-web-1'; then
    diagnose_web || true
  fi

  if curl -fsS -o /dev/null http://localhost:3000/ 2>/dev/null; then
    echo "OK: http://localhost:3000/ répond"
    remove_rule || true
    exit 0
  fi

  docker logs --tail=50 openbastion-web-1 2>/dev/null || true
  echo "Le port 3000 n'est pas encore prêt; nouvelle tentative..."
  sleep 2

done

echo "Échec après $max_attempts tentatives : http://localhost:3000/ reste indisponible" >&2

remove_rule || true
exit 1
