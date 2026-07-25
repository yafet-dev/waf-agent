# Geo Access Control

Block or allow traffic by country, per domain.

## How it works

Every rule is keyed by domain. The first request for a domain provisions all
the nginx files it needs and adds one include to its server block, so a new
site works with no manual setup.

Created per domain (`example.com` shown):

| Path | Purpose |
| --- | --- |
| `/etc/nginx/waf/geo-lists/example.com.allow` | Allowed country codes, `ET 1;` per line |
| `/etc/nginx/waf/geo-lists/example.com.deny` | Denied country codes |
| `/etc/nginx/conf.d/waf-geo-example.com.conf` | `map` blocks turning the visitor's country into two flags |
| `/etc/nginx/waf/geo-servers/example.com.allow_only.conf` | `if ($geo_allow_example_com = 0) { return 403; }` |
| `/etc/nginx/waf/geo-servers/example.com.deny_only.conf` | `if ($geo_deny_example_com) { return 403; }` |
| `/etc/nginx/waf/geo-servers/example.com.active.conf` | Includes whichever mode is active |

And one line is added inside **every** `server` block that serves the domain:

```nginx
include /etc/nginx/waf/geo-servers/example.com.active.conf;
```

### How the server block is found

By its `server_name` directive, not its filename. A vhost is routinely stored
under an unrelated name — `gnzabe-apis.conf` containing
`server_name gnzabe.com www.gnzabe.com;` is a real example — and a
filename-based lookup finds nothing there.

The agent scans `sites-enabled`, `sites-available` and `conf.d`, resolves
symlinks so edits land on the real file, parses each `server { … }` block with
brace tracking (so a `location` block does not end the scan early), ignores
commented-out directives, and matches exact names, `.example.com` and
`*.example.com` forms. The catch-all `server_name _;` is **not** treated as a
match — it is the default server, not a claim to serve your domain.

A domain usually appears in two blocks (the `:80` redirect and the `:443`
server); both receive the include, so a request is filtered before the
redirect.

### If no server block serves the domain

The request **fails** with HTTP 409 and nothing is applied.

This is deliberate. It previously logged a warning and returned success: the
lists were written, nginx reloaded, HTTP 200 came back and the database was
updated, while nginx never evaluated the rule. An administrator saw "Ethiopia
blocked" in the UI and traffic from Ethiopia continued to arrive. A security
control that quietly does nothing is worse than one that refuses.

To fix a 409, ensure some server block declares `server_name yourdomain.com;`.

The map blocks live in `conf.d` because nginx only accepts `map` in the `http`
context, and the stock nginx.conf already carries
`include /etc/nginx/conf.d/*.conf;` there. Nothing has to edit nginx.conf.

Each domain gets its own nginx variables (`$geo_allow_example_com`), so domains
never interfere with each other.

## Prerequisite: the GeoIP2 module and a country database

Enforcement needs nginx to know each visitor's country. **Without this, nothing
below will work** — `nginx -t` fails and the agent rolls the change back rather
than pretending it applied.

```bash
sudo apt install libnginx-mod-http-geoip2
```

Then a country database. Two options:

| | MaxMind GeoLite2 | DB-IP Lite |
| --- | --- | --- |
| Cost | Free | Free |
| Signup | Account + licence key required | None, direct download |
| Licence | MaxMind EULA | CC BY 4.0 — **requires visible attribution** |

DB-IP is easier to automate (no credentials); MaxMind avoids the attribution
obligation. Either produces an `.mmdb` file.

Point nginx at it in the `http` context, e.g. `/etc/nginx/conf.d/00-geoip2.conf`:

```nginx
geoip2 /etc/nginx/geoip/country.mmdb {
    $geoip2_country_code source=$remote_addr country iso_code;
}
```

The `00-` prefix matters: `conf.d` loads alphabetically and this must come
before the per-domain map files that reference the variable.

If your setup exposes a different variable name, tell the agent:

```bash
GEO_COUNTRY_VARIABLE='$geoip2_data_country_code'
```

Verify:

```bash
sudo nginx -t && curl -s localhost:8080/v1/geo/status
```

## API

All endpoints are scoped by domain. Authentication follows the agent's normal
rule — a bearer token unless the caller is on loopback (see the README).

```bash
# Set the mode for a domain
POST /v1/geo/{domain}/mode          {"mode": "allow_only" | "deny_only", "force": false}

# Country lists
POST   /v1/geo/{domain}/allow       {"country": "ET"}
DELETE /v1/geo/{domain}/allow/{country}?force=false
POST   /v1/geo/{domain}/deny        {"country": "CN"}
DELETE /v1/geo/{domain}/deny/{country}

# Status
GET /v1/geo/{domain}/status         one domain
GET /v1/geo/status                  every configured domain
```

### Modes

- **`deny_only`** — everyone is allowed except the listed countries. An empty
  deny list blocks nobody, which is how a new domain starts.
- **`allow_only`** — only the listed countries are allowed. Switching to this
  with an empty allow list would block all traffic, so it is refused unless you
  pass `force=true`.

### Example

```bash
# Block China and Russia on gnzabe.com
curl -X POST localhost:8080/v1/geo/gnzabe.com/deny \
     -H 'Content-Type: application/json' -d '{"country":"CN"}'
curl -X POST localhost:8080/v1/geo/gnzabe.com/deny \
     -H 'Content-Type: application/json' -d '{"country":"RU"}'
curl -X POST localhost:8080/v1/geo/gnzabe.com/mode \
     -H 'Content-Type: application/json' -d '{"mode":"deny_only"}'

curl localhost:8080/v1/geo/gnzabe.com/status
# {
#   "domain": "gnzabe.com",
#   "mode": "deny_only",
#   "allow": [],
#   "deny": ["CN","RU"],
#   "enforced": true,
#   "enforced_in": ["/etc/nginx/sites-available/gnzabe-apis.conf"]
# }
```

`enforced` is the field that matters. Rules can exist on disk with no vhost
referencing them, so the status reports whether nginx is actually applying them
and names the files where the include lives.

## Safety

- Every change is written to a temp file and renamed, so nginx never reads a
  half-written file.
- After each change the agent runs `nginx -t`. **If the test fails the previous
  contents are restored** and an error is returned, so a bad rule cannot take
  the site down.
- Editing a country list still works when the domain's vhost does not exist
  yet. The files are written and enforcement begins once the site is deployed.
- Domain names are validated against a strict hostname pattern before touching
  the filesystem — `../` and similar are rejected outright.

## Troubleshooting

**`{"mode":"unknown","allow":[],"deny":[]}`**
The domain has no geo configuration yet. That is the correct answer for an
untouched domain; reading status never creates anything. Set a mode or add a
country and it will provision.

**`nginx -t` fails mentioning `$geoip2_country_code`**
The GeoIP2 module or its database is missing — see the prerequisite above. The
agent detects this case and adds a hint to the error.

**Rules exist but traffic is not blocked**
Ask the agent whether it is enforcing:

```bash
curl localhost:8080/v1/geo/gnzabe.com/status
```

If `"enforced": false`, no server block includes the rule. Confirm directly:

```bash
grep -rn 'geo-servers' /etc/nginx/sites-available/ /etc/nginx/sites-enabled/
```

Re-send any geo request for the domain and the agent will add the include, or
return 409 naming the problem if no block declares the domain.

If `"enforced": true` but traffic still gets through, the rule is wired in and
the cause is upstream: the GeoIP2 database is missing or is not resolving that
visitor to the country you expect.

**HTTP 409 "No nginx server block serves ..."**
No `server_name` directive anywhere declares that domain. Check for a typo, or
that the site is deployed:

```bash
grep -rn 'server_name' /etc/nginx/sites-enabled/
```
