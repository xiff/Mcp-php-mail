#!/usr/bin/env bash
# Vérifie depuis l'extérieur qu'aucun fichier sensible n'est servi et que /mcp exige un jeton.
# Usage : bin/check-exposure.sh https://mcp.mondomaine.ch
set -u
BASE="${1:?URL de base requise}"
fail=0
for p in /config/config.php /config/keys/private.key /var/app.sqlite /var/log/audit.log /vendor/autoload.php \
         /composer.json /composer.lock /.git/config /.git/HEAD /.htaccess /.env /src/App.php /bin/revoke-all.php /index.php~; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE$p")
  if [ "$code" = "200" ]; then echo "EXPOSÉ  $p ($code)"; fail=1; else echo "ok      $p ($code)"; fi
done
hdr=$(curl -s -D - -o /dev/null -X POST "$BASE/mcp" -H 'Content-Type: application/json' -d '{}')
echo "$hdr" | grep -q '^HTTP/[0-9.]* 401' && echo "$hdr" | grep -qi '^www-authenticate: Bearer resource_metadata=' \
  && echo "ok      /mcp sans jeton -> 401 + resource_metadata" || { echo "ÉCHEC   /mcp sans jeton"; fail=1; }
code=$(curl -s -o /dev/null -w '%{http_code}' "http://${BASE#https://}/mcp")
[ "$code" = "301" ] || [ "$code" = "308" ] && echo "ok      HTTP -> HTTPS ($code)" || { echo "ÉCHEC   redirection HTTPS ($code)"; fail=1; }
exit $fail
