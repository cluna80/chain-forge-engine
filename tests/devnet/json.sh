# json.sh — tiny JSON helpers for the devnet scripts (source it).
#
# Plain grep/sed/sort, so the scripts run anywhere bash runs, including Git
# Bash on Windows, where `python3` is often missing or a Store stub.
# Enough for flat values in our own API responses and key files; not a
# general JSON parser.

# Print the first value of "field" (string or number) from JSON on stdin.
json_field() {
    tr -d '\n' | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\(\"[^\"]*\"\|-\{0,1\}[0-9][0-9]*\)" | head -1 \
        | sed 's/^"[^"]*"[[:space:]]*:[[:space:]]*//; s/^"//; s/"$//'
}

# Print the largest "height" in JSON on stdin (e.g. /api/blocks); 0 if none.
json_max_height() {
    local h
    h=$(grep -o '"height"[[:space:]]*:[[:space:]]*[0-9][0-9]*' | grep -o '[0-9][0-9]*$' | sort -n | tail -1)
    echo "${h:-0}"
}
