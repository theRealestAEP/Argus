#!/bin/sh
set -eu

target=$1
attacker=$2
state_root=$3
output=$4

mkdir -p "$output"
if docker inspect "$target" >/dev/null 2>&1; then
	docker logs "$target" >"$output/target.log" 2>&1 || true
	mkdir -p "$output/argus"
	docker cp "$target:$state_root/logs/events.jsonl" \
		"$output/argus/events.jsonl" >/dev/null 2>&1 || true
	for directory in reports containment-receipts agent-events/rejected broker-rejected; do
		if docker exec "$target" sh -c \
			'test -n "$(find "$1" -type f -print -quit 2>/dev/null)"' \
			sh "$state_root/$directory"
		then
			destination=$(printf '%s' "$directory" | tr '/' '-')
			docker cp "$target:$state_root/$directory" \
				"$output/argus/$destination" >/dev/null 2>&1 || true
		fi
	done
fi
if docker inspect "$attacker" >/dev/null 2>&1; then
	docker logs "$attacker" >"$output/attacker.log" 2>&1 || true
	docker cp "$attacker:/tmp/pi-sessions" \
		"$output/attacker-session" >/dev/null 2>&1 || true
fi

{
	printf '%s\n\n' "Empty artifact classes are omitted."
	find "$output" -type f ! -name contents.txt -print | sort
} >"$output/contents.txt"
