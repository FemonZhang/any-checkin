# AnyRouter Daily Check-in

A dependency-free Python script for daily, multi-account AnyRouter check-in.
It handles the site WAF challenge, cookie authentication, retries, rate
limiting, and rotating logs.

## Setup

1. Edit `accounts.json`.
2. Add a browser cookie and the matching user ID for each account.
3. Run one cycle:

```powershell
python anyrouter_checkin.py --once
```

For a long-running daily scheduler:

```powershell
python anyrouter_checkin.py --schedule
```

The scheduler runs once on startup, then every day at `schedule_time`
(`08:05` by default) in Asia/Shanghai. `jitter_seconds` adds a random delay of
up to five minutes by default.

## Cookie Configuration

Each enabled account needs the complete `Cookie` request header and the
matching numeric user ID:

```json
{
  "cookie": "session=...; other_cookie=...",
  "user_id": 12345
}
```

`name` is optional. If omitted, the script uses `account-1`, `account-2`,
and so on. `enabled` is also optional and defaults to `true`.

`user_id` is required. AnyRouter expects it in the `New-API-User` request
header, and it cannot be recovered from the Cookie string.

To obtain these values, open AnyRouter while logged in, then inspect a
successful `/api/...` request in the browser Network panel. Copy its complete
`Cookie` request header. In Local Storage, open `user` and use its `id` value
as `user_id`.

Cookies are checked against `/api/user/self` before check-in. Expired or
incorrect cookies are reported without performing the check-in request. The
session can expire, so refresh the cookie values when the log reports a 401 or
403 response.

## Proxy

`"proxy": "auto"` reads the Windows system proxy, then falls back to
`HTTPS_PROXY`. Override it from the command line:

```powershell
python anyrouter_checkin.py --once --proxy http://127.0.0.1:7897
```

Use `--direct` to bypass all proxies. `--time` and `--jitter` override the
schedule without editing the config.

## Logs And Exit Codes

Logs are written to `logs/anyrouter-checkin.log`, rotated daily at midnight,
and kept for seven calendar days. A one-shot run exits with `0` when no
account failed, `1` when at least one account failed, and `2` for
configuration errors.

## Tests

```powershell
python -m unittest discover -s tests -v
```
