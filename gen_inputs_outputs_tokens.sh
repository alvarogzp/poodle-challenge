#!/bin/sh

TOKENS_FILE="daemon/tokens"
SUBMIT_PATH="submit"
TEST_PATH="test"

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

echo "{" > "$TOKENS_FILE"
for i in $(seq 0 $(( ${1:-10} - 1 )))
do
	csrf="$(get_random_data 10 | one_line)"
	echo "$csrf" > "$TEST_PATH/input$i"
	echo "$csrf" > "$SUBMIT_PATH/input$i"
	
	user="$(get_random_data 4 | starting_with "[a-z]" | one_line)"
	password="$(get_random_data 10 | one_line)"
	encoded_user_password="$(base64_encode "$user:$password")"
	echo "$encoded_user_password" > "$TEST_PATH/output$i"
	echo "$encoded_user_password" > "$SUBMIT_PATH/output$i"
	
	echo "\t\"$csrf\": \"$encoded_user_password\"," >> "$TOKENS_FILE"
done
echo "}" >> "$TOKENS_FILE"
