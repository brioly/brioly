#!/bin/sh
# Builds the table of end-of-support dates that brioly.io serves at
# https://brioly.io/lifecycle/v1/data.json, which the brioly CLI and brioly
# Cloud read to write version-support.md. The dates come from endoflife.date,
# a public, MIT-licensed collection (https://endoflife.date). Nothing about
# the caller is sent: these are plain GETs of public files.
#
#   scripts/update-lifecycle.sh OUTPUT.json
#
# The table is not part of the brioly binary. Whoever serves it runs this
# and publishes the result; a mirror inside a closed network does the same
# and points brioly at it with BRIOLY_LIFECYCLE_URL.
#
# Needs curl and jq.
set -eu

out="${1:?usage: update-lifecycle.sh OUTPUT.json}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# id on endoflife.date | name shown in documents
products='amazon-eks|Amazon EKS
kubernetes|Kubernetes
aws-lambda|AWS Lambda runtime
amazon-rds-postgresql|Amazon RDS for PostgreSQL
amazon-aurora-postgresql|Amazon Aurora PostgreSQL
amazon-rds-mysql|Amazon RDS for MySQL
amazon-aurora-mysql|Amazon Aurora MySQL
amazon-rds-mariadb|Amazon RDS for MariaDB
nodejs|Node.js
python|Python
go|Go
ruby|Ruby
php|PHP
eclipse-temurin|Eclipse Temurin (Java)
dotnet|.NET
nginx|nginx
alpine-linux|Alpine Linux
debian|Debian
ubuntu|Ubuntu
redis|Redis
postgresql|PostgreSQL
mysql|MySQL
nextjs|Next.js
angular|Angular
nuxt|Nuxt'

echo "$products" | while IFS='|' read -r id name; do
  curl -fsS "https://endoflife.date/api/$id.json" -o "$tmp/$id.raw"
  # eol is a date, false (no end announced) or true (ended, date not given).
  jq --arg id "$id" --arg name "$name" '{
      key: $id,
      value: {
        name: $name,
        cycles: [ .[] | {
          cycle: (.cycle | tostring),
          eol: (if (.eol | type) == "string" then .eol elif .eol == true then "ended" else "" end),
          extended: (if (.extendedSupport | type) == "string" then .extendedSupport else "" end)
        } ]
      }
    }' "$tmp/$id.raw" > "$tmp/$id.json"
done

jq -s --arg updated "$(date -u +%Y-%m-%d)" \
  '{updated: $updated, source: "https://endoflife.date", products: from_entries}' \
  "$tmp"/*.json > "$out"
echo "wrote $out"
