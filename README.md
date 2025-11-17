# goscanner

`goscanner` is an agentless network discovery and asset inventory tool that scans configurable IP ranges, fingerprints the reachable devices, and pushes normalized assets into GLPI via its REST API. It is designed to run from a central scanner VM and scales to multiple sites by combining lightweight discovery workers with profile-driven configuration.

## Features

- **Configurable discovery profiles** – assign custom port sets, worker pools, and timeouts per range or site.
- **Agentless liveness detection** – TCP SYN dialing against well-known service ports to identify active hosts.
- **Pluggable fingerprinting** – HTTP/S inspection and normalized asset modeling ready for enrichment with SNMP/SSH modules.
- **GLPI integration** – REST API upsert client that reuses the GLPI session token and prevents duplicate assets.
- **Scheduler-ready** – reusable scheduler component for periodic scans plus a CLI for ad-hoc runs.

## Project layout

```
cmd/goscanner       # CLI entrypoint
pkg/config          # YAML configuration loader
pkg/discovery       # CIDR expansion and liveness engine
pkg/fingerprint     # Host fingerprint modules
pkg/glpi            # REST API client
pkg/inventory       # Asset model + normalizer
pkg/logging         # Logger factory
pkg/scheduler       # Periodic task runner
```

## Quick start

1. Copy the sample configuration file and update it for your environment:

   ```bash
   cp goscanner.example.yaml goscanner.yaml
   $EDITOR goscanner.yaml
   ```

2. Run a discovery:

   ```bash
   go run ./cmd/goscanner --config goscanner.yaml --command scan
   ```

3. List configured ranges:

   ```bash
   go run ./cmd/goscanner --config goscanner.yaml --command list
   ```

The scanner prints a summary of discovered assets and, when GLPI credentials are provided, will upsert the normalized assets into your GLPI instance.

## Configuring GLPI authentication

The scanner supports both GLPI API flavors:

- **High-level JSON:API (`api.php/v2.x`)** – configure the `glpi.oauth` block with the OAuth client ID/secret and the GLPI username/password the scanner should impersonate. Tokens are requested using the password grant (`/api.php/token`) and automatically refreshed when they expire. Leave the password empty to be prompted at runtime so you do not have to store credentials on disk.
- **Legacy REST API (`apirest.php`)** – set `glpi.user_token` (and optionally `glpi.app_token`). The client will keep using the historical session-token workflow via `initSession`.

At runtime the scanner determines which authentication method to use based on the fields provided in `goscanner.yaml`, so you can keep both sections in the file and switch by simply pointing `glpi.base_url` at the desired API endpoint.

## Logging & troubleshooting

- Set `logging.level: debug` in `goscanner.yaml` to enable verbose diagnostics. This surfaces when a site/range starts, how many hosts were examined, and every GLPI upsert attempt so you can follow long-running scans in real time.
- `logging.path` can redirect output to a file (default is stdout). This is helpful for scheduled runs or when collecting logs for support.
- When using the legacy API, the GLPI REST client requires a `user_token` (found under **Users → {user} → API token**). Supplying an `app_token` is optional; if your GLPI instance enforces API clients you can paste the token from **Setup → General → API**.
- When targeting the JSON:API endpoint, provide the OAuth client info documented under **Setup → OAuth Clients** alongside the GLPI username/password. The scanner defaults to the `api` scope but you can override it via `glpi.oauth.scope` if necessary.
- Set `glpi.base_url` to whichever API endpoint your GLPI release documents (for example `https://glpi.example.com/api.php/v2.1` for the JSON:API implementation or `https://glpi.example.com/apirest.php` for the legacy REST API). The scanner honors the path exactly as configured so you can target either flavor without editing the binary.
- When GLPI rejects authentication the scanner now reports the HTTP status and message body so you immediately see whether the token is invalid or missing permissions.
