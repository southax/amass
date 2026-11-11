<h1 align="center">Amass + ndxer</h1>

<p align="center">
<b>Give Amass one domain: it also enumerates the other domains ndxer links to the same owner, with every data source.</b><br>
<a href="#quick-start">Quick start</a> •
<a href="#what-you-get">What you get</a> •
<a href="#recipes">Recipes</a> •
<a href="#settings">Settings</a> •
<a href="#units-plans-and-rate-limits">Units and plans</a> •
<a href="#troubleshooting">Troubleshooting</a>
</p>

This is [OWASP Amass](https://github.com/owasp-amass/amass) with [ndxer](https://ndxer.com/) built in. ndxer reads
DNS both ways: from a domain to its names, and from a value back to every domain that publishes it. Give this build a
domain and an ndxer API key, and it adds two things to an Amass session:

1. **Related scope.** With an ndxer key, this build asks ndxer which other domains it links to the same owner, such
   as `example.net` or `example.org`, and adds them to the session's scope, so every Amass plugin enumerates them as
   if you had passed them with `-d`. This is **on by default**. The terminal says what was added and why, what was
   left out, and what it cost.
2. **The `ndxer` data source** lists the hostnames ndxer has observed under every domain in scope. That covers names
   with DNS records of their own, and also hosts that other records point at: CNAME targets, mail servers, name
   servers, SPF includes and SOA primaries. They land in the same asset database as every other source's, so
   `amass subs`, `amass viz` and the rest read them as usual.

Everything else works the same as the original Amass: every other plugin, every flag, the asset database.

---

## Quick start

### 1. Get an ndxer API key

1. Create an account at **https://ndxer.com/accounts/signup/**. The Free plan works, but read
   [units and plans](#units-plans-and-rate-limits) first.
2. Open **https://ndxer.com/app/api-keys/** and create a key.
3. Copy it straight away, because it is shown only once. It looks like `ndx_live_<8 characters>_<43 characters>`.

Check that the key works. This call is free:

```sh
export NDXER_API_KEY='ndx_live_...'
curl -s -H "Authorization: Bearer $NDXER_API_KEY" https://api.ndxer.com/v1/me/
```

You should see your `plan_key` and a `usage` block with `remaining` units. A `401 unauthenticated` means the key
was mistyped or revoked.

**One key for every ndxer integration.** The [subfinder build](https://github.com/southax/subfinder) reads the same
`NDXER_API_KEY`, so one line in `~/.bashrc` or `~/.zshrc` sets up both.

### 2. Install

You need **Go 1.26 or newer** (`go version`).

```sh
go install -v github.com/southax/amass/v5/cmd/amass@ndxer
```

- Use **`@ndxer`.** The build lives on the `ndxer` branch and this repository publishes no version tags of its own.
- The binary is called `amass` and lands in `$(go env GOPATH)/bin`. It **replaces** any other `amass` installed
  there.

Or build from source:

```sh
git clone -b ndxer https://github.com/southax/amass && cd amass
go build -o amass ./cmd/amass
```

### 3. Give Amass the key

The plugin reads `NDXER_API_KEY` from the environment:

```sh
export NDXER_API_KEY='ndx_live_...'       # add this to ~/.bashrc or ~/.zshrc to keep it
```

Or put it in Amass's data source config, `~/.config/amass/datasources.yaml` (created on first run), under
`datasources:`:

```yaml
datasources:
  - name: ndxer
    creds:
      account:
        apikey: ndx_live_KEYID_SECRET
```

You only need one of the two. The config file wins when both are set.

**Amass runs its work in a background engine.** `amass enum` starts it the first time and it keeps running. The
engine reads `NDXER_API_KEY` and the [settings](#settings) when it starts, so:

- set them in the shell **before** the first `amass enum`;
- after changing one, stop the engine (`pkill -f "amass engine"`) and run `amass enum` again;
- if you run the engine yourself (`amass engine`, a service, Docker), set them in that environment.

### 4. First run

```sh
amass enum -d example.com
```

The ndxer lines appear on the terminal above the progress bar (see the next section). When the run ends, list the
names:

```sh
amass subs -names -d example.com
```

`amass subs` lists only the domains you name. To see the names under the domains ndxer added, name them too; the
"added" line on the terminal lists them:

```sh
amass subs -names -d example.com,example.net,example.org
```

---

## What you get

### Related scope: the terminal lines

For every domain you pass, the terminal shows lines like these. The format is real; the domains are placeholders.

```text
ndxer related scope for example.com: added 2 domains ndxer links to the same owner; amass enumerates them with every data source
  example.net  subject  Publishes dns0.example.com, under the seed's own name.
  example.org  subject  Shares the verification token example-site-verification=Q2xhdWRlIGV4YW1wbGUgdG9rZW4, issued to one account.
ndxer related scope for example.com: NOT added: 12 review domains (weaker evidence of the same owner); include them with NDXER_RELATED_CLASSES=subject,review
ndxer related scope for example.com: 4 shared signals belong to infrastructure providers, not to the subject; never added
ndxer related scope for example.com: 5 units charged (1 pages); each added domain's hostnames listing is charged on top
```

How to read them:

| Line | Meaning |
|---|---|
| **added N domains** | Domains ndxer proposes as the owner's own (class `subject`). They are added to the session scope, so every Amass plugin enumerates them. |
| **one line per added domain** | The domain, its class and ndxer's most decisive reason, in ndxer's own words. |
| **NOT added: review** | Weaker evidence of the same owner. Counted here; each one, with its reason, is in the session log. Add them with `NDXER_RELATED_CLASSES=subject,review`. |
| **shared signals … never added** | Values that belong to infrastructure providers, such as a hosting company's name servers. They are never used to add domains. |
| **units charged** | What the related lookup cost, and a reminder that each added domain also costs its hostnames listing. |

The session log (`session-<id>.log` in Amass's output directory, `~/.config/amass` by default) has every line as
JSON, including each review domain with its class, reason and the shared values behind it. The same answer is
available as raw JSON or in ndxer's investigation page:

```sh
curl -s -H "Authorization: Bearer $NDXER_API_KEY" "https://api.ndxer.com/v1/related/?q=example.com"
# https://ndxer.com/app/investigations/?q=example.com
```

A **subject** class is a proposal made from evidence. Before you treat an added domain as in scope for a test, look
at the evidence. **One hop only:** domains ndxer added get their hostnames listed, but no related lookup of their own.
With `-rigid`, nothing is added: the lines list what ndxer found and say it was not added because rigid boundaries are
on.

### Hostnames under every domain in scope

The `ndxer` data source makes one paged lookup per domain in scope. Every host comes back once, lower-cased and
deduplicated. It follows pages until the list ends, so you get the whole list and not a sample.

### Waiting for complete lists

For a domain ndxer has not seen before, it may answer "still looking it up" for a short while. For a domain it already
holds, it answers at once and may say the list is partial, because more is still being added. In both cases this
build **waits for the complete list by default**, up to 15 minutes per domain and list, and says so once:

```text
ndxer is still adding hostnames for example.com. Waiting up to 15 minutes for the complete list; set NDXER_NO_WAIT=1 to use what is there now instead
```

Amass's other plugins keep working while it waits. With `NDXER_NO_WAIT=1` the list is used as it is and flagged:

```text
WARN ndxer hostnames for example.com are partial: ndxer was still adding to them, and NDXER_NO_WAIT is set, so this run did not wait (kept 415). Run amass again in a few minutes to get the rest, or unset NDXER_NO_WAIT to wait for them
```

---

## Recipes

```sh
# Everything: every plugin, ndxer included, plus related scope
amass enum -d example.com

# Stock Amass scope plus the ndxer data source (no domains added)
NDXER_NO_RELATED=1 amass enum -d example.com

# Widest scope: add review-class domains too
NDXER_RELATED_CLASSES=subject,review amass enum -d example.com

# Related scope reported but not added (Amass's own switch)
amass enum -d example.com -rigid

# Don't wait for lists ndxer is still adding to
NDXER_NO_WAIT=1 amass enum -d example.com

# Many domains from a file
amass enum -df domains.txt

# The names under your domain and under the domains ndxer added
amass subs -names -d example.com,example.net,example.org

# Only the ndxer lines from the last session log
jq -r 'select(.plugin.name == "ndxer") | .msg' ~/.config/amass/session-*.log
```

Remember that the engine reads the `NDXER_*` variables when it starts: after changing one, stop it
(`pkill -f "amass engine"`) before the next run.

---

## Settings

Amass has no per-plugin command-line flags, so this build is set with environment variables. They match the subfinder
build's flags one for one:

| Environment variable | Default | subfinder build | What it does |
|---|---|---|---|
| `NDXER_API_KEY` | none | same variable | Your API key. Or the `ndxer` block in `datasources.yaml`. |
| `NDXER_RELATED_CLASSES` | `subject` | `-ndxer-related-classes` | Which related domains to add: `subject`, or `subject,review` for the widest scope. `infrastructure` is refused, because those domains belong to a provider. |
| `NDXER_NO_RELATED` | off | `-no-ndxer-related` | `1` turns related scope off. You get stock Amass scope, with the ndxer data source still running. |
| `NDXER_NO_WAIT` | off | `-ndxer-no-wait` | `1` uses ndxer's lists as they are when ndxer is still adding to them, instead of waiting for the complete ones. Each list used this way is flagged. |
| `AMASS_ENGINE_PORT` | `4000` | none | The port the engine listens on, for when 4000 is taken. Set it for both `amass engine` and `amass enum`. |

These Amass flags matter most with ndxer:

| Flag | Use with ndxer |
|---|---|
| `-rigid` | No domains are added; ndxer's related lines still list them. |
| `-d`, `-df` | The domains ndxer runs on. Each gets its own related lookup. |
| `-dir` | Where the asset database and the session log go. |
| `-silent` | No progress bar and no ndxer lines on the terminal; the session log still has them. |

Everything else is Amass's own: run `amass enum -h`, or read the [Amass docs](https://owasp-amass.github.io/docs).

---

## Units, plans and rate limits

Every ndxer request costs units from your monthly allowance. Plans differ in volume, not features: every plan
includes both lookups this build uses. Each plan's units per month, hosts per page and requests per minute are on the
[pricing page](https://ndxer.com/pricing/). `GET /v1/me/` (free) shows how many units you have left.

What a run costs:

- **The ndxer data source:** 1 unit per page, for every domain in scope: the ones you passed and every domain related
  scope adds. Larger plans return more hosts per page, so the same domain takes fewer pages and fewer units.
- **The related lookup:** once per domain you pass, 1 unit plus 1 per shared value scored on the first page (at most
  8 units), then 1 unit for each further page. The terminal prints the exact charge.
- **Waiting for a complete list costs nothing extra.** The repeats while ndxer finishes are free.
- **Large organisations add many domains.** One organisation's domain can bring in hundreds of subject domains, and
  each costs at least one unit. On a small plan, start with `NDXER_NO_RELATED=1` and turn related scope on for the
  domains you care about, or move to a larger plan.

**ndxer stops early rather than spend your allowance on a list it can't finish.** If the first page shows that
listing a domain would need more units than you have left this month, the data source keeps that page (1 unit), stops
and says how many units finishing needs and how many are left. The related lookup stops the same way.

The plugin paces itself at about two requests a second and retries on its own: on HTTP 429 it waits the
`Retry-After` the API sends; on 502, 503 and 504, and on a response cut off before it ends, it retries with
exponential backoff and jitter, at most 5 attempts per request. Other errors, such as a bad key or an exhausted
allowance, are not retried.

---

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| No `ndxer` lines at all | No key reached the engine, or a plain Amass binary is running | Set `NDXER_API_KEY`, stop the engine (`pkill -f "amass engine"`), run again. Check `which amass`. |
| `unauthenticated: Invalid or revoked API key. (HTTP 401)` | Wrong or revoked key | Create a new key at https://ndxer.com/app/api-keys/ and check it with `/v1/me/`. Related scope stays off for the rest of the session. |
| `quota_exceeded`, or `kept N names from the first page` | This month's units are used up | Wait for the period to end, raise your plan, or use `NDXER_NO_RELATED=1`. |
| `rate_limited` / HTTP 429, or `gave up after 5 attempts` | Requests arrive faster than your plan takes them | Run one Amass session per key at a time. |
| `ndxer was still looking up example.com after 15m0s; run again shortly` | ndxer had not seen the domain before and was still looking it up after the whole wait | Run again in a few minutes. Waiting costs no units. |
| `ndxer hostnames for example.com are partial` | ndxer was still adding to the list, and either `NDXER_NO_WAIT` was set or the wait ran out | Run again in a few minutes to get the rest. |
| `could not add example.net` | Amass accepts only registered domains into its scope, or the asset store refused the write | The domain is still listed in the line; pass it with `-d` yourself. |
| Changed an `NDXER_*` variable and nothing changed | The running engine still has the old environment | Stop the engine (`pkill -f "amass engine"`) and run again. |
| `The Amass engine did not respond` | Port 4000 is taken by something else | Set `AMASS_ENGINE_PORT` to a free port for both commands. |

ndxer's API errors include a `request_id`. Quote it when you contact ndxer support. To call the API directly, see the
[API docs](https://ndxer.com/docs/) and the [OpenAPI contract](https://api.ndxer.com/v1/openapi.json).

---

## About this build

- It is based on Amass `v5.1.1` and kept current with Amass's `main` branch.
- **This build is not affiliated with or endorsed by OWASP or the Amass project.** Amass is their work,
  Apache-2.0-licensed; see [LICENSE](LICENSE) and [NOTICE](NOTICE), which lists what this build changes. For every
  other plugin, its API keys, the full flag list, Docker images and the asset database, see the
  [Amass README](https://github.com/owasp-amass/amass#readme) and the [Amass docs](https://owasp-amass.github.io/docs).
