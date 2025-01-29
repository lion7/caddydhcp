# Caddy DHCP module

This is a Caddy App module that starts a DHCP server.

The handler modules are basically a rewritten version of the plugins of https://github.com/coredhcp/coredhcp/.
Kudos to the CoreDHCP team for doing the heavy lifting.

Configuration of this server is very similar to how Caddy's HTTP server is configured.
Note that there is no adapter yet for a Caddyfile, so JSON is currently the only configuration method.

## Installation

Build with xcaddy:

```bash
xcaddy build --with=github.com/lion7/caddydhcp
```

Optional: add capabilities to the binary to listen on privileged port 67:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./caddy
```

## Configuration

Create a Caddy JSON configuration, in this example saved as `caddy.json`:

```json
{
  "apps": {
    "dhcp": {
      "servers": {
        "srv0": {
          "logs": true,
          "interface": "lo",
          "handle": [
            {
              "handler": "file",
              "filename": "leases.txt",
              "autoRefresh": true
            }
          ]
        }
      }
    }
  }
}
```

Note that by default this module will listen on `udp4/:69`, `udp6/:547`, `udp6/[ff02::1:2]:547` and `udp6/[ff05::1:3]:547`.

## Running

Run the binary with the above config:

```bash
./caddy run --config caddy.json
```
