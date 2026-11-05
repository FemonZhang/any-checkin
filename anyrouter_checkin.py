#!/usr/bin/env python3
"""Daily multi-account check-in for AnyRouter.

The script uses only the Python standard library. It solves the site's
JavaScript WAF challenge, authenticates with a browser session cookie, then
calls the check-in endpoint once per account.
"""

from __future__ import annotations

import argparse
import gzip
import http.cookiejar
import json
import logging
import logging.handlers
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from datetime import datetime, time as day_time, timedelta, timezone
from pathlib import Path
from typing import Any


BASE_URL = "https://anyrouter.top"
SIGN_IN_PATH = "/api/user/sign_in"
USER_SELF_PATH = "/api/user/self"
LOG_RETENTION_DAYS = 7

CHALLENGE_KEY = bytes.fromhex("3000176000856006061501533003690027800375")
CHALLENGE_PERMUTATION = [
    0xF,
    0x23,
    0x1D,
    0x18,
    0x21,
    0x10,
    0x01,
    0x26,
    0x0A,
    0x09,
    0x13,
    0x1F,
    0x28,
    0x1B,
    0x16,
    0x17,
    0x19,
    0x0D,
    0x06,
    0x0B,
    0x27,
    0x12,
    0x14,
    0x08,
    0x0E,
    0x15,
    0x20,
    0x1A,
    0x02,
    0x1E,
    0x07,
    0x04,
    0x11,
    0x05,
    0x03,
    0x1C,
    0x22,
    0x25,
    0x0C,
    0x24,
]
CHALLENGE_ARG_RE = re.compile(r"arg1\s*=\s*['\"]([0-9A-Fa-f]{40})['\"]")

CHINA_TZ = timezone(timedelta(hours=8), name="Asia/Shanghai")
ALREADY_SIGNED_MARKERS = (
    "\u4eca\u65e5\u5df2\u7b7e\u5230",
    "\u4eca\u5929\u5df2\u7b7e\u5230",
    "\u5df2\u7ecf\u7b7e\u5230",
    "\u91cd\u590d\u7b7e\u5230",
    "\u660e\u5929\u518d\u6765",
)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/155.0.0.0 Safari/537.36"
)


class CheckinError(Exception):
    """Base exception for expected check-in failures."""


class AuthenticationError(CheckinError):
    """The account could not authenticate."""


class ChallengeError(CheckinError):
    """The site challenge could not be solved."""


class TransientError(CheckinError):
    """A retryable network or server failure."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ProtocolError(CheckinError):
    """The server returned an unexpected response."""


@dataclass(frozen=True)
class Account:
    name: str
    enabled: bool = True
    cookie: str | None = None
    user_id: str | int | None = None


@dataclass(frozen=True)
class AppConfig:
    base_url: str
    proxy: str
    schedule_time: day_time
    jitter_seconds: int
    request_timeout_seconds: float
    retries: int
    account_delay_min_seconds: float
    account_delay_max_seconds: float
    log_file: Path
    accounts: tuple[Account, ...]


@dataclass(frozen=True)
class ApiResponse:
    status: int
    headers: Any
    body: bytes

    def json(self) -> dict[str, Any]:
        try:
            value = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            preview = self.body[:300].decode("utf-8", errors="replace")
            raise ProtocolError(
                f"Expected JSON but received HTTP {self.status}: {preview!r}"
            ) from exc
        if not isinstance(value, dict):
            raise ProtocolError("Expected a JSON object from the API")
        return value


@dataclass(frozen=True)
class AccountResult:
    name: str
    status: str
    message: str
    elapsed_seconds: float


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run scheduled multi-account check-in for AnyRouter."
    )
    parser.add_argument(
        "--config",
        default="accounts.json",
        help="Path to the JSON configuration file (default: accounts.json).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once",
        action="store_true",
        help="Run one cycle immediately, then exit (default).",
    )
    mode.add_argument(
        "--schedule",
        action="store_true",
        help="Run immediately, then keep running on the configured daily schedule.",
    )
    parser.add_argument(
        "--time",
        dest="schedule_time",
        help="Override the daily schedule time, for example 08:05.",
    )
    parser.add_argument(
        "--jitter",
        type=int,
        help="Override the maximum random delay after the scheduled time.",
    )
    parser.add_argument(
        "--proxy",
        help="Override proxy URL, for example http://127.0.0.1:7897.",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Disable proxy detection and connect directly.",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="Console and file log level (default: INFO).",
    )
    return parser.parse_args(argv)


def parse_schedule_time(value: str) -> day_time:
    try:
        hour_text, minute_text = value.strip().split(":", 1)
        return day_time(int(hour_text), int(minute_text))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid schedule time {value!r}; expected HH:MM") from exc


def _number(
    data: dict[str, Any],
    key: str,
    default: float,
    *,
    minimum: float = 0,
) -> float:
    value = data.get(key, default)
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be numeric") from exc
    if number < minimum:
        raise ValueError(f"{key} must be at least {minimum}")
    return number


def load_config(path: Path) -> AppConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Config file not found: {path}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read config file {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("The config root must be a JSON object")

    raw_accounts = raw.get("accounts")
    if not isinstance(raw_accounts, list):
        raise ValueError("accounts must be a JSON array")

    accounts: list[Account] = []
    names: set[str] = set()
    for index, item in enumerate(raw_accounts, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"accounts[{index - 1}] must be an object")
        name = str(item.get("name") or f"account-{index}").strip()
        if not name:
            raise ValueError(f"accounts[{index - 1}].name must not be empty")
        if name in names:
            raise ValueError(f"Duplicate account name: {name}")
        names.add(name)

        user_id = item.get("user_id")
        account = Account(
            name=name,
            enabled=bool(item.get("enabled", True)),
            cookie=_optional_string(item.get("cookie")),
            user_id=user_id if isinstance(user_id, (str, int)) else None,
        )
        _validate_account(account)
        accounts.append(account)

    if not any(account.enabled for account in accounts):
        raise ValueError("At least one enabled account is required")

    schedule_text = str(raw.get("schedule_time", "08:05"))
    jitter_seconds = int(_number(raw, "jitter_seconds", 300, minimum=0))
    request_timeout = _number(raw, "request_timeout_seconds", 30, minimum=1)
    retries = int(_number(raw, "retries", 3, minimum=0))
    delay_min = _number(raw, "account_delay_min_seconds", 2, minimum=0)
    delay_max = _number(raw, "account_delay_max_seconds", 6, minimum=0)
    if delay_max < delay_min:
        raise ValueError(
            "account_delay_max_seconds must be greater than or equal to "
            "account_delay_min_seconds"
        )

    base_url = str(raw.get("base_url") or BASE_URL).rstrip("/")
    parsed_base = urllib.parse.urlsplit(base_url)
    if parsed_base.scheme not in ("http", "https") or not parsed_base.netloc:
        raise ValueError("base_url must be an absolute HTTP(S) URL")

    log_file = Path(str(raw.get("log_file") or "logs/anyrouter-checkin.log"))
    proxy = str(raw.get("proxy") or "auto")

    return AppConfig(
        base_url=base_url,
        proxy=proxy,
        schedule_time=parse_schedule_time(schedule_text),
        jitter_seconds=jitter_seconds,
        request_timeout_seconds=request_timeout,
        retries=retries,
        account_delay_min_seconds=delay_min,
        account_delay_max_seconds=delay_max,
        log_file=log_file,
        accounts=tuple(accounts),
    )


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _validate_account(account: Account) -> None:
    if not account.enabled:
        return
    if not account.cookie:
        raise ValueError(f"Account {account.name!r} has no cookie")
    if account.user_id is None or not str(account.user_id).strip():
        raise ValueError(f"Account {account.name!r} has no user_id")


def configure_logging(log_file: Path, level_name: str) -> None:
    level = getattr(logging, level_name.upper())
    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)

    # The active file represents today, so six backups give seven calendar days.
    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_file,
        when="midnight",
        interval=1,
        backupCount=LOG_RETENTION_DAYS - 1,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(console)
    root.addHandler(file_handler)


def _unsbox(value: str) -> str:
    if len(value) != len(CHALLENGE_PERMUTATION):
        raise ChallengeError("Unexpected challenge token length")
    output = [""] * len(CHALLENGE_PERMUTATION)
    for source_index, character in enumerate(value):
        target_position = source_index + 1
        for bucket_index, bucket_position in enumerate(CHALLENGE_PERMUTATION):
            if bucket_position == target_position:
                output[bucket_index] = character
                break
    if any(not character for character in output):
        raise ChallengeError("The challenge token was not fully permuted")
    return "".join(output)


def solve_challenge_cookie(html: str) -> str:
    match = CHALLENGE_ARG_RE.search(html)
    if not match:
        raise ChallengeError("No arg1 token found in the challenge page")
    try:
        permuted = bytes.fromhex(_unsbox(match.group(1)))
    except ValueError as exc:
        raise ChallengeError("The challenge token is not valid hex") from exc
    if len(permuted) != len(CHALLENGE_KEY):
        raise ChallengeError("The challenge token has an unexpected size")
    return bytes(left ^ right for left, right in zip(permuted, CHALLENGE_KEY)).hex()


def _is_challenge(body: bytes) -> bool:
    if b"arg1" not in body or b"acw_sc__v2" not in body:
        return False
    sample = body[:20000].decode("utf-8", errors="ignore")
    return bool(CHALLENGE_ARG_RE.search(sample))


def _decode_response_body(body: bytes, content_encoding: str) -> bytes:
    encoding = content_encoding.lower().strip()
    if not body or not encoding or encoding == "identity":
        return body
    if "gzip" in encoding:
        return gzip.decompress(body)
    if "deflate" in encoding:
        return zlib.decompress(body)
    if "br" in encoding:
        raise ProtocolError(
            "The server returned Brotli content; disable the upstream proxy "
            "compression or install a Brotli decoder"
        )
    raise ProtocolError(f"Unsupported Content-Encoding: {content_encoding}")


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def windows_system_proxy() -> str | None:
    if os.name != "nt":
        return None
    try:
        import winreg

        key_path = (
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not enabled:
                return None
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
    except (ImportError, OSError):
        return None
    text = str(server or "").strip()
    if not text:
        return None
    if "=" in text:
        entries: dict[str, str] = {}
        for part in text.split(";"):
            if "=" in part:
                scheme, address = part.split("=", 1)
                entries[scheme.strip().lower()] = address.strip()
        text = entries.get("https") or entries.get("http") or ""
    if not text:
        return None
    if "://" not in text:
        text = f"http://{text}"
    return text


def resolve_proxy(value: str) -> str | None:
    normalized = (value or "auto").strip()
    if normalized.lower() in ("direct", "none", "off", "false"):
        return None
    if normalized.lower() != "auto":
        return normalized if "://" in normalized else f"http://{normalized}"
    system = windows_system_proxy()
    if system:
        return system
    return (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )


class AnyRouterSession:
    def __init__(
        self,
        base_url: str,
        proxy: str | None,
        timeout: float,
        retries: int,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.host = urllib.parse.urlsplit(self.base_url).hostname
        if not self.host:
            raise ValueError("The base URL has no hostname")
        self.timeout = timeout
        self.retries = retries
        self.cookies = http.cookiejar.CookieJar()

        handlers: list[Any] = [
            urllib.request.HTTPCookieProcessor(self.cookies),
        ]
        if proxy:
            handlers.append(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            )
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        self.opener = urllib.request.build_opener(*handlers)

    def load_cookie_string(self, cookie_header: str) -> None:
        cleaned = cookie_header.strip()
        if cleaned.lower().startswith("cookie:"):
            cleaned = cleaned.split(":", 1)[1].strip()
        pairs = [part.strip() for part in cleaned.split(";") if part.strip()]
        if not pairs:
            raise AuthenticationError("The configured cookie string is empty")
        for pair in pairs:
            if "=" not in pair:
                raise AuthenticationError(
                    f"Invalid cookie segment (missing '='): {pair!r}"
                )
            name, value = pair.split("=", 1)
            name = name.strip()
            if not name:
                raise AuthenticationError("A cookie name is empty")
            self._set_cookie(name, value.strip())

    def _set_cookie(self, name: str, value: str) -> None:
        cookie = http.cookiejar.Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=self.host,
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=self.base_url.startswith("https://"),
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        )
        self.cookies.set_cookie(cookie)

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urllib.parse.urljoin(f"{self.base_url}/", path_or_url.lstrip("/"))

    def _raw_request(
        self,
        method: str,
        path_or_url: str,
        *,
        payload: bytes | None,
        headers: dict[str, str],
    ) -> ApiResponse:
        request_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.7",
            "Cache-Control": "no-store",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/login",
            "User-Agent": DEFAULT_USER_AGENT,
        }
        request_headers.update(headers)
        request = urllib.request.Request(
            self._url(path_or_url),
            data=payload,
            headers=request_headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read()
                decoded = _decode_response_body(
                    body, response.headers.get("Content-Encoding", "")
                )
                return ApiResponse(response.status, response.headers, decoded)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            decoded = _decode_response_body(
                body, exc.headers.get("Content-Encoding", "")
            )
            return ApiResponse(exc.code, exc.headers, decoded)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise TransientError(f"Network error: {exc}") from exc

    def _request_with_challenge(
        self,
        method: str,
        path_or_url: str,
        *,
        payload: bytes | None,
        headers: dict[str, str],
    ) -> ApiResponse:
        for challenge_attempt in range(3):
            response = self._raw_request(
                method,
                path_or_url,
                payload=payload,
                headers=headers,
            )
            if not _is_challenge(response.body):
                return response
            cookie_value = solve_challenge_cookie(
                response.body.decode("utf-8", errors="ignore")
            )
            logging.debug(
                "Solved site challenge (attempt %s)",
                challenge_attempt + 1,
            )
            self._set_cookie("acw_sc__v2", cookie_value)
        raise ChallengeError("The site challenge repeated three times")

    def request_json(
        self,
        method: str,
        path_or_url: str,
        *,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        allow_statuses: tuple[int, ...] = (),
    ) -> tuple[ApiResponse, dict[str, Any]]:
        payload = None
        request_headers = dict(headers or {})
        if data is not None:
            payload = json.dumps(
                data,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        last_error: TransientError | None = None
        for attempt in range(self.retries + 1):
            try:
                response = self._request_with_challenge(
                    method,
                    path_or_url,
                    payload=payload,
                    headers=request_headers,
                )
                if response.status == 429 or response.status >= 500:
                    retry_after = _parse_retry_after(
                        response.headers.get("Retry-After")
                    )
                    raise TransientError(
                        f"Temporary server response HTTP {response.status}",
                        retry_after=retry_after,
                    )
                if (
                    response.status < 200
                    or response.status >= 300
                    and response.status not in allow_statuses
                ):
                    return response, response.json() if response.body else {}
                return response, response.json() if response.body else {}
            except TransientError as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                delay = exc.retry_after
                if delay is None:
                    delay = min(30.0, 2.0**attempt)
                logging.warning(
                    "%s; retrying in %.1fs (%s/%s)",
                    exc,
                    delay,
                    attempt + 1,
                    self.retries,
                )
                time.sleep(delay)
        raise last_error or TransientError("Request failed")


def _extract_user_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("id", "user_id"):
        value = payload.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value)
    nested = payload.get("user")
    if isinstance(nested, dict):
        return _extract_user_id(nested)
    return None


def authenticate(session: AnyRouterSession, account: Account) -> str:
    if not account.cookie or account.user_id is None:
        raise AuthenticationError("Cookie and user_id are required")
    user_id = str(account.user_id)
    session.load_cookie_string(account.cookie)

    response, payload = session.request_json(
        "GET",
        USER_SELF_PATH,
        headers={
            "New-API-User": user_id,
            "Referer": f"{session.base_url}/console/personal",
        },
        allow_statuses=(401, 403),
    )
    if response.status in (401, 403):
        message = str(payload.get("message") or f"HTTP {response.status}")
        raise AuthenticationError(
            f"Cookie rejected or expired: {message}"
        )
    if not payload.get("success"):
        message = str(payload.get("message") or "Cookie verification failed")
        raise AuthenticationError(message)

    actual_user_id = _extract_user_id(payload.get("data"))
    if actual_user_id and actual_user_id != user_id:
        raise AuthenticationError(
            f"Configured user_id {user_id} does not match session user "
            f"{actual_user_id}"
        )
    return user_id


def is_already_signed(message: str) -> bool:
    normalized = message.strip().lower().replace(" ", "")
    return any(
        marker.lower().replace(" ", "") in normalized
        for marker in ALREADY_SIGNED_MARKERS
    )


def check_in_account(
    config: AppConfig,
    account: Account,
    proxy: str | None,
) -> AccountResult:
    started = time.monotonic()
    if not account.enabled:
        return AccountResult(account.name, "disabled", "Account disabled", 0.0)

    try:
        session = AnyRouterSession(
            config.base_url,
            proxy,
            config.request_timeout_seconds,
            config.retries,
        )
        user_id = authenticate(session, account)
        response, payload = session.request_json(
            "POST",
            SIGN_IN_PATH,
            headers={
                "New-API-User": user_id,
                "Referer": f"{config.base_url}/console/personal",
            },
            allow_statuses=(401, 403),
        )
        elapsed = time.monotonic() - started

        message = str(payload.get("message") or "").strip()
        if response.status in (401, 403):
            return AccountResult(
                account.name,
                "failed",
                message or f"Session rejected with HTTP {response.status}",
                elapsed,
            )
        if payload.get("success"):
            return AccountResult(
                account.name,
                "signed",
                message or "Check-in succeeded",
                elapsed,
            )
        if is_already_signed(message):
            return AccountResult(
                account.name,
                "already_signed",
                message,
                elapsed,
            )
        return AccountResult(
            account.name,
            "failed",
            message or f"HTTP {response.status}",
            elapsed,
        )
    except CheckinError as exc:
        elapsed = time.monotonic() - started
        return AccountResult(account.name, "failed", str(exc), elapsed)
    except Exception:
        logging.exception("Unexpected error while processing %s", account.name)
        elapsed = time.monotonic() - started
        return AccountResult(
            account.name,
            "failed",
            "Unexpected internal error; see log",
            elapsed,
        )


def run_all_accounts(config: AppConfig, proxy: str | None) -> list[AccountResult]:
    enabled = [account for account in config.accounts if account.enabled]
    logging.info("Starting check-in for %s enabled account(s)", len(enabled))
    if not enabled:
        logging.warning("No enabled accounts are configured")
        return []

    results: list[AccountResult] = []
    for index, account in enumerate(enabled):
        result = check_in_account(config, account, proxy)
        results.append(result)
        logging.info(
            "%s: %s - %s (%.1fs)",
            result.name,
            result.status,
            result.message,
            result.elapsed_seconds,
        )
        if index < len(enabled) - 1:
            delay = random.uniform(
                config.account_delay_min_seconds,
                config.account_delay_max_seconds,
            )
            if delay > 0:
                logging.info("Waiting %.1fs before the next account", delay)
                time.sleep(delay)

    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    logging.info(
        "Cycle complete: %s",
        ", ".join(f"{key}={value}" for key, value in sorted(counts.items())),
    )
    return results


def next_scheduled_time(
    now: datetime,
    target: day_time,
    jitter_seconds: int,
) -> datetime:
    candidate = datetime.combine(now.date(), target, tzinfo=CHINA_TZ)
    if jitter_seconds > 0:
        candidate += timedelta(seconds=random.randint(0, jitter_seconds))
    if candidate <= now:
        candidate = datetime.combine(
            now.date() + timedelta(days=1),
            target,
            tzinfo=CHINA_TZ,
        )
        if jitter_seconds > 0:
            candidate += timedelta(seconds=random.randint(0, jitter_seconds))
    return candidate


def sleep_until(target: datetime) -> None:
    while True:
        remaining = (target - datetime.now(CHINA_TZ)).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 300.0))


def run_schedule(config: AppConfig, proxy: str | None) -> int:
    logging.info(
        "Scheduler started; daily check-in at %s Asia/Shanghai, jitter 0-%ss",
        config.schedule_time.strftime("%H:%M"),
        config.jitter_seconds,
    )
    run_all_accounts(config, proxy)
    while True:
        next_run = next_scheduled_time(
            datetime.now(CHINA_TZ),
            config.schedule_time,
            config.jitter_seconds,
        )
        logging.info("Next check-in: %s", next_run.strftime("%Y-%m-%d %H:%M:%S %z"))
        sleep_until(next_run)
        run_all_accounts(config, proxy)


def _has_failure(results: list[AccountResult]) -> bool:
    return any(result.status == "failed" for result in results)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config_path = Path(args.config).expanduser().resolve()
    try:
        config = load_config(config_path)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.schedule_time:
        try:
            config = AppConfig(
                **{
                    **config.__dict__,
                    "schedule_time": parse_schedule_time(args.schedule_time),
                }
            )
        except ValueError as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2
    if args.jitter is not None:
        if args.jitter < 0:
            print("Configuration error: --jitter cannot be negative", file=sys.stderr)
            return 2
        config = AppConfig(**{**config.__dict__, "jitter_seconds": args.jitter})

    proxy = None if args.direct else resolve_proxy(args.proxy or config.proxy)
    if args.direct and args.proxy:
        print(
            "Configuration error: --direct and --proxy cannot be used together",
            file=sys.stderr,
        )
        return 2

    try:
        configure_logging(config.log_file, args.log_level)
    except OSError as exc:
        print(f"Could not initialize logging: {exc}", file=sys.stderr)
        return 2

    logging.info("Loaded config: %s", config_path)
    logging.info(
        "HTTP mode: %s",
        f"proxy {proxy}" if proxy else "direct",
    )

    if args.schedule:
        try:
            return run_schedule(config, proxy)
        except KeyboardInterrupt:
            logging.info("Scheduler stopped")
            return 130

    results = run_all_accounts(config, proxy)
    return 1 if _has_failure(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
