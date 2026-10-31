#!/usr/bin/env bash
set -euo pipefail

compose_file="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/docker-compose.yml"
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

add_rules() {
	local rule
	for rule in "${rules[@]}"; do
		sudo -n iptables-legacy -I FORWARD 1 ${rule}
	done
}

remove_rule() {
	local rule
	for rule in "${rules[@]}"; do
		sudo -n iptables-legacy -D FORWARD ${rule} >/dev/null 2>&1 || true
	done
}

cleanup_failed_start() {
	status=$?
	if [[ $status -ne 0 && $rule_added -eq 1 ]]; then
		remove_rule || true
	fi
}

build_rules

case "${1:-}" in
	up)
		if ! rule_exists; then
			add_rules
			rule_added=1
		fi
		trap cleanup_failed_start EXIT
		docker compose -f "$compose_file" up -d --build --wait
		rule_added=0
		printf 'Prévisualisation active. Arrête-la avec: bash %s down\n' "$0"
		;;
	reset)
		if ! rule_exists; then
			add_rules
			rule_added=1
		fi
		trap cleanup_failed_start EXIT
		docker compose -f "$compose_file" down --remove-orphans -v
		docker compose -f "$compose_file" up -d --build --wait
		rule_added=0
		printf 'Prévisualisation réinitialisée. Arrête-la avec: bash %s down\n' "$0"
		;;
	down)
		set +e
		docker compose -f "$compose_file" down
		compose_status=$?
		remove_rule
		rule_status=$?
		if [[ $compose_status -ne 0 ]]; then
			exit "$compose_status"
		fi
		exit "$rule_status"
		;;
	*)
		printf 'Usage: bash %s {up|down|reset}\n' "$0" >&2
		exit 2
		;;
esac