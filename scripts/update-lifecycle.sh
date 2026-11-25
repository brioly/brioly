#!/bin/sh
# Refreshes pkg/lifecycle/data.json: when each version of the products brioly
# recognises stops being supported. The dates come from endoflife.date, a
# public, MIT-licensed collection (https://endoflife.date). Nothing about
# the caller is sent: these are plain GETs of public files.
#
# brioly never fetches these dates while it runs. They are part of the
# binary, so the same scan gives the same document everywhere, online or
# not; run this script and commit the result to bring them up to date.
#
# Needs curl and jq.
set -eu

out="$(dirname "$0")/../pkg/lifecycle/data.json"
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
