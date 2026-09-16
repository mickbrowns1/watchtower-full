# Local Splunk sink, exposed via Tailscale Funnel

Optional add-on to the main Watchtower stack: a local, free-license Splunk
Enterprise instance that receives a copy of the same event stream, reachable
from the public internet through [Tailscale
Funnel](https://tailscale.com/kb/1223/funnel) so a cloud-side destination
(e.g. a SentinelOne Data Pipelines "Splunk HEC Logs" destination) can reach
it without you managing your own TLS cert or opening a router port.

**There is no Splunk Universal Forwarder in this stack.** Events reach this
Splunk instance over HTTP Event Collector (HEC) only — nothing runs a UF
agent anywhere. "Funnel" is not a custom tool either — it's Tailscale's own
built-in `tailscale funnel` subcommand, run inside the `ts-splunk` container.

## Components

Two services, added to the main `docker-compose.yml`:

- **`ts-splunk`** — a `tailscale/tailscale` sidecar. Joins your tailnet,
  publishes Splunk Web (8000) and HEC (8088), and is the container that
  actually runs `tailscale funnel`.
- **`splunk`** (container name `splunk-free`) — `splunk/splunk:latest`,
  free license. Runs with `network_mode: service:ts-splunk`, i.e. it shares
  `ts-splunk`'s network namespace rather than getting its own — this is
  what lets Funnel (which only runs from `ts-splunk`) expose a port that's
  actually bound inside `splunk-free`.

Not started by default — `docker compose up -d` for the main stack does not
touch these unless you explicitly bring them up too (see below), so this is
safe to skip entirely if you don't need a Splunk sink.

## Install

1. Add to `.env` (see `.env.example` at the repo root):
   ```
   TS_AUTHKEY=tskey-auth-...   # from https://login.tailscale.com/admin/settings/keys
   SPLUNK_PASSWORD=<a password, 8+ chars>
   ```

2. Start both containers:
   ```bash
   docker compose up -d ts-splunk splunk
   ```

3. Wait for `splunk-free` to report healthy — first boot runs Splunk's full
   provisioning pass and can take several minutes:
   ```bash
   docker inspect splunk-free --format '{{.State.Health.Status}}'
   ```

4. **Apply the CPU-precheck patch before you ever restart the container**
   (see Gotcha 1 below) — otherwise any later restart crash-loops it:
   ```bash
   docker run --rm -v watchtower-full_splunk_etc:/etc alpine sh -c \
     "printf '\nSPLUNK_SKIP_PREINSTALL_CPU_CHECKS_CORRUPTING_DATA_IF_UNSUPPORTED=1\n' >> /etc/splunk-launch.conf"
   ```
   (Swap the volume name for whatever `docker volume ls` actually shows —
   it's prefixed with your Compose project name, which is normally the
   repo's directory name unless you've overridden it.)

5. Log into Splunk Web at `http://localhost:8000` (`admin` / your
   `SPLUNK_PASSWORD`). Create an index if you want one other than `main`
   (Settings → Indexes → New Index), then Settings → Data Inputs → HTTP
   Event Collector → New Token to create a HEC token. Note the token GUID.

6. Expose HEC publicly via Funnel:
   ```bash
   ./splunk/setup-funnel.sh
   ```
   This runs (and is safe to re-run any time):
   ```bash
   docker exec ts-splunk tailscale funnel --bg --https=443 https+insecure://localhost:8088
   docker exec ts-splunk tailscale funnel status
   ```
   Check status any time with the second line alone. Your public HEC URL
   will look like `https://<your-tailnet-hostname>.<your-tailnet>.ts.net`
   (port 443 implied — **do not** append `:8088`, Funnel only ever serves
   443/8443/10000 and a different port suffix will simply fail to connect).

7. Test end-to-end:
   ```bash
   curl -k https://<your-funnel-hostname>/services/collector/event \
     -H "Authorization: Splunk <your HEC token>" \
     -d '{"event":{"test":"hi"},"sourcetype":"_json"}'
   ```
   Expect `{"text":"Success","code":0}`, then confirm the event actually
   landed by searching the index in Splunk Web — a `200`/`Success` from HEC
   does not guarantee the event was indexed (see Gotcha 5).

## The `tailscale funnel` command, in full

```bash
docker exec ts-splunk tailscale funnel --bg --https=443 https+insecure://localhost:8088
```

- `--bg` — persist the Funnel config in the background instead of running
  in the foreground for the life of the command.
- `--https=443` — the public-facing port. Funnel only ever exposes 443,
  8443, or 10000; you cannot pick an arbitrary port here.
- `https+insecure://localhost:8088` — the backend target *inside the
  container*. Must be `https+insecure`, not `http`, because Splunk's HEC
  listener has `enableSSL=1` with a self-signed cert.

Funnel's config lives in Tailscale's own state file, bind-mounted at
`./splunk/tailscale-data`. It survives container restarts, and is lost only
if that directory is wiped or the node re-registers as a new tailnet
identity — re-run `setup-funnel.sh` any time you need to reapply it.

## Wiring into the pipeline

This local Splunk instance is a **destination for a copy of your data**, not
a replacement for anything already in the stack. Two independent things
need to both be true for events to land here:

1. `nexus-sgcia` keeps forwarding to SentinelOne's own DataPipeline HEC
   ingest exactly as before (`HEC_URL`/`HEC_TOKEN` in `.env`, unchanged).
2. In the SentinelOne Data Pipelines console, add a **Destination** of type
   "Splunk HEC Logs" pointed at your Funnel URL (from step 6 above) and the
   HEC token you created in step 5. **Endpoint must be the bare Funnel
   hostname with no port suffix** — appending `:8088` will silently fail.

With both configured, SentinelOne's own Data Pipelines product is what
forwards a copy of ingested events out to this local Splunk over the
internet via Funnel — `nexus-sgcia`'s own config (`sgcia/config.yaml`) does
not need any changes for this to work.

## Gotchas

1. **Volume/project-name mismatch silently orphans data.** Docker Compose
   names volumes using the project name, which defaults to the containing
   directory's name. If you ever run `docker compose` for this stack from a
   differently-named directory (or a differently-invoked context), you'll
   get differently-prefixed volumes and it'll look like your Splunk
   instance — and its HEC tokens — reset to empty. Pin a `name:` at the top
   of `docker-compose.yml` if you need to guarantee this never happens.

2. **Restarting `ts-splunk` alone breaks `splunk-free`.** Because
   `splunk-free` shares `ts-splunk`'s network namespace
   (`network_mode: service:ts-splunk`), restarting `ts-splunk` rebuilds that
   namespace out from under `splunk-free`, which stays "running" per Docker
   but becomes unreachable. Always restart both together:
   ```bash
   docker compose restart ts-splunk splunk
   ```

3. **Fatal CPU-precheck bug on restart, Apple Silicon specific.** Running
   the `linux/amd64` Splunk image under emulation, any restart against
   already-provisioned `/opt/splunk/etc` data triggers an "upgrade
   migration" path that hard-checks for AVX instructions and fails. The
   documented bypass env var
   (`SPLUNK_SKIP_PREINSTALL_CPU_CHECKS_CORRUPTING_DATA_IF_UNSUPPORTED=1`,
   already set in `docker-compose.yml`) does not reach this specific check
   — the Ansible task that actually starts Splunk as the `splunk` user has
   no `environment:` clause, so the var never propagates. The real fix is
   install step 4 above: append the same var directly into
   `/opt/splunk/etc/splunk-launch.conf` inside the volume once, before the
   first restart. Skip this and `restart: unless-stopped` will crash-loop
   the container forever after any restart.

4. **Funnel protocol mismatch causes permanent 502s.** The backend target
   must be `https+insecure://localhost:8088`, not `http://localhost:8088`
   — HEC requires TLS on 8088, so plain HTTP 502s on every request.

5. **Funnel only serves 443/8443/10000.** A destination endpoint with
   `:8088` appended will not connect — use the bare Funnel hostname.

6. **HEC can silently drop events even after returning `Success`.** If a
   token's sourcetype is `_json` and the payload isn't valid JSON,
   `JsonLineBreaker` drops it — logged only in `splunkd.log`, not surfaced
   in the HEC response. Always verify by searching the index, not just by
   checking the curl response code.

7. **Don't commit secrets.** `TS_AUTHKEY` and `SPLUNK_PASSWORD` belong in
   `.env` only (already gitignored at the repo root) — never hardcode them
   in `docker-compose.yml`.
