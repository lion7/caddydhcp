# Caddy DHCP module

This is a Caddy App module that starts a DHCP server.

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
          "interfaces": [
            "lo"
          ],
          "addresses": [
            "0.0.0.0:69"
          ],
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

Note that by default this module will listen on `0.0.0.0:69` and `[::]:547`.
A minimal configuration:

```json
{
  "apps": {
    "dhcp": {
      "servers": {
        "srv0": {
        }
      }
    }
  }
}
```

## Running

Run the binary with the above config:

```bash
./caddy run --config caddy.json
```
