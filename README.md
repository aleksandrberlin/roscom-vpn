# roscom-vpn

sing-box domain rule-sets, auto-built from plain text lists.

## Download URLs (latest)

| List | .srs (binary) | .json (source) |
|------|---------------|----------------|
| all (combined) | [all.srs](https://github.com/aleksandrberlin/roscom-vpn/releases/latest/download/all.srs) | [all.json](https://github.com/aleksandrberlin/roscom-vpn/blob/main/output/json/all.json) |
| claude | [claude.srs](https://github.com/aleksandrberlin/roscom-vpn/releases/latest/download/claude.srs) | [claude.json](https://github.com/aleksandrberlin/roscom-vpn/blob/main/output/json/claude.json) |
| openai | [openai.srs](https://github.com/aleksandrberlin/roscom-vpn/releases/latest/download/openai.srs) | [openai.json](https://github.com/aleksandrberlin/roscom-vpn/blob/main/output/json/openai.json) |
| samsungsmartthings | [samsungsmartthings.srs](https://github.com/aleksandrberlin/roscom-vpn/releases/latest/download/samsungsmartthings.srs) | [samsungsmartthings.json](https://github.com/aleksandrberlin/roscom-vpn/blob/main/output/json/samsungsmartthings.json) |

## sing-box config example

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "roscom-vpn",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/aleksandrberlin/roscom-vpn/releases/latest/download/all.srs"
      }
    ],
    "rules": [
      {
        "rule_set": "roscom-vpn",
        "outbound": "proxy"
      }
    ]
  }
}
```

## Adding domains

Add or edit `.txt` files in `lists/` — one domain per line, `#` for comments. Push to `main` and the GitHub Action rebuilds everything.

## Local build

```sh
python convert.py
```

Generates `output/json/*.json` and `output/srs/*.srs`.
