#!/usr/bin/env bash

set -o pipefail

curdir="$(dirname $0)"

EXTERNAL_env_name=out
FIRST_env_name=ns1
SECOND_env_name=ns2
 
cleanup() {
	ip link del dev ${EXTERNAL_env_name}_to_${FIRST_env_name}
	ip link del dev ${EXTERNAL_env_name}_to_${SECOND_env_name}
	ip netns delete ${FIRST_env_name}
	ip netns delete ${SECOND_env_name}
}

setup_env() {
	# Ensure that /var/run/netns is writable
	mount -t tmpfs tmpfs /var/run/netns
 
	ip netns add ${FIRST_env_name}
	ip netns add ${SECOND_env_name}

	ip link add ${EXTERNAL_env_name}_to_${FIRST_env_name} type veth peer name ${FIRST_env_name}_to_${EXTERNAL_env_name}
	ip link add ${FIRST_env_name}_to_${SECOND_env_name} type veth peer name ${SECOND_env_name}_to_${FIRST_env_name}
	ip link add ${EXTERNAL_env_name}_to_${SECOND_env_name} type veth peer name ${SECOND_env_name}_to_${EXTERNAL_env_name}

	ip link set dev ${FIRST_env_name}_to_${EXTERNAL_env_name} netns ${FIRST_env_name}
	ip link set dev ${SECOND_env_name}_to_${EXTERNAL_env_name} netns ${SECOND_env_name}
	ip link set dev ${SECOND_env_name}_to_${FIRST_env_name} netns ${SECOND_env_name}
	ip link set dev ${FIRST_env_name}_to_${SECOND_env_name} netns ${FIRST_env_name}
}

#trap cleanup 'EXIT'

global_setup() {
	cargo build --release --examples

}

ERRORS=()

load_test() {
	local test_name=$1
	local test_file_base="${curdir}/tests/${test_name}"

	setup_env

	bash "${test_file_base}.sh" >"${test_file_base}.output" 2>&1
	[[ $? -ne 0 ]] && ERRORS+=("${test_name}: Non-zero return")
	if [[ -f "${test_file_base}.expected_output" ]]; then
		[[ $(diff "${test_file_base}.output" "${test_file_base}.expected_output" | wc -c) -gt 0 ]] && ERRORS+=("${test_name}: Invalid output")

	fi

	cleanup

}

global_setup
load_test run_examples

if [[ ${#ERRORS[@]} -gt 0 ]]; then
	echo "Got errors:"
	for error in "${ERRORS[@]}"; do
		echo "${error}"
	done

	exit 1
fi
