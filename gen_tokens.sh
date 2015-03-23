#!/bin/sh

get_random_data()
{
	local wide="$1"
	base64 -w "$wide" < /dev/urandom | grep -v "/\|+"
}

starting_with()
{
	local start="$1"
	grep "^$start"
}

one_line()
{
	head --lines=1
}

base64_encode()
{
	echo -n "$1" | base64
}

echo "{"
for i in $(seq ${1:-10})
do
	csrf="$(get_random_data 10 | one_line)"
	user="$(get_random_data 4 | starting_with "[a-z]" | one_line)"
	password="$(get_random_data 10 | one_line)"
	encoded_user_password="$(base64_encode "$user:$password")"
	echo "\t\"$csrf\": \"$encoded_user_password\","
done
echo "}"
