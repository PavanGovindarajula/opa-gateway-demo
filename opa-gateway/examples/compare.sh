#!/bin/sh
set -eu
request='{"tool":"export_documents","classification":"restricted","destination":"","roles":["reviewer"]}'
for pair in 'dry-run:8081' 'enforce:8082'; do
  name=${pair%:*}; port=${pair#*:}
  printf '\n%s\n' "$name"
  curl --silent --show-error -w '\nHTTP %{http_code}\n' -H 'Content-Type: application/json' -d "$request" "http://localhost:$port/v1/tools/invoke"
done
