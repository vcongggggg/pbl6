import hashlib
import math
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any


@dataclass
class RateLimitResult:
    """Outcome of rate limit policy evaluation for an IP and endpoint."""

    is_limited: bool
    current_count: int
    limit: int
    remaining: int
    retry_after: int
    window_seconds: float
    scope: str
    client_ip: str
    tracking_key: str = ""
    violations_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serializes rate limit result into dictionary format."""
        return {
            "is_limited": self.is_limited,
            "current_count": self.current_count,
            "limit": self.limit,
            "remaining": self.remaining,
            "retry_after": self.retry_after,
            "window_seconds": self.window_seconds,
            "scope": self.scope,
            "client_ip": self.client_ip,
            "tracking_key": self.tracking_key,
            "violations_count": self.violations_count,
        }


class SlidingWindowRateLimiter:
    """In-memory thread-safe sliding window rate limiter with exponential backoff & session scoping.

    Implements O(1) sliding window eviction using timestamp deques in RAM.
    Conforms to:
      - OWASP API Security Top 10 (2023) - API4:2023 Unrestricted Resource Consumption
      - OWASP ModSecurity CRS v4.0 HTTP Flood & Brute-force Defense
      - NIST SP 800-115 Automated Attack Mitigation & HTTP 429 Retry-After
      - Repeat Offender Defense: Exponential Backoff Throttling (600s cycle)
      - Anti-NAT Collision Defense: Fingerprint & Session-Aware Composite Scoping
      - Hardened Dual-Tier Limiting: IP-level Hard Cap + Fingerprint LRU (SEC-PBL6-001)
    """

    DEFAULT_WINDOW_SECONDS: float = 60.0
    DEFAULT_GLOBAL_LIMIT: int = 60
    DEFAULT_SENSITIVE_LIMITS: dict[str, int] = {
        "auth": 10,       # Max 10 login attempts per minute (Brute-force protection)
        "admin": 15,      # Max 15 admin operations per minute
        "files": 20,      # Max 20 file downloads per minute
    }
    VIOLATION_WINDOW_SECONDS: float = 600.0  # 10 minutes tracking window for repeat offenders
    BASE_BACKOFF_RETRY_AFTER: int = 120      # Base backoff for 3rd violation (seconds)
    MAX_BACKOFF_RETRY_AFTER: int = 900       # Maximum backoff penalty cap (15 minutes)
    MAX_TRACKED_KEYS: int = 50000            # LRU bound to eliminate unbounded memory DoS

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        default_limit: int = DEFAULT_GLOBAL_LIMIT,
        sensitive_limits: dict[str, int] | None = None,
    ) -> None:
        """Initializes rate limiter with sliding window duration and limits."""
        self.window_seconds = window_seconds
        self.default_limit = default_limit
        self.sensitive_limits = (
            dict(sensitive_limits) if sensitive_limits is not None else dict(self.DEFAULT_SENSITIVE_LIMITS)
        )
        self._records: OrderedDict[str, deque[float]] = OrderedDict()
        self._violation_history: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def resolve_scope(self, path: str) -> str:
        """Determines rate limit scope based on requested endpoint."""
        normalized_path = path.lower().strip()
        if "auth" in normalized_path or "login" in normalized_path:
            return "auth"
        if "admin" in normalized_path or "ping" in normalized_path:
            return "admin"
        if "files" in normalized_path or "download" in normalized_path:
            return "files"
        return "global"

    def generate_tracking_key(
        self,
        client_ip: str,
        scope: str,
        session_id: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Generates composite tracking key combining IP, session, or user-agent fingerprint.

        Prevents false-positive throttling for distinct clients behind shared NAT/proxies.
        """
        if session_id and session_id.strip():
            return f"{client_ip}::sess_{session_id.strip()}::{scope}"
        if user_agent and user_agent.strip():
            ua_hash = hashlib.md5(user_agent.strip().encode("utf-8")).hexdigest()[:6]
            return f"{client_ip}::ua_{ua_hash}::{scope}"
        return f"{client_ip}:{scope}"

    def check_rate_limit(
        self,
        client_ip: str,
        path: str = "",
        risk_penalty: bool = False,
        custom_limit: int | None = None,
        now: float | None = None,
        session_id: str | None = None,
        user_agent: str | None = None,
    ) -> RateLimitResult:
        """Checks whether the client IP / fingerprint has exceeded the allowed request frequency.

        Enforces a hardened 2-tier check (SEC-PBL6-001):
          Tier 1: IP-level Hard Cap (effective_limit for auth; 3 * effective_limit for others)
          Tier 2: Composite Session/Fingerprint key limit
        """
        if now is None:
            now = time.time()

        scope = self.resolve_scope(path)
        base_limit = custom_limit if custom_limit is not None else self.sensitive_limits.get(scope, self.default_limit)

        if risk_penalty:
            effective_limit = max(1, base_limit // 2)
        else:
            effective_limit = max(1, base_limit)

        ip_cap = effective_limit if scope == "auth" else effective_limit * 3
        ip_key = f"{client_ip}::__ip_cap__::{scope}"
        fp_key = self.generate_tracking_key(client_ip, scope, session_id, user_agent)
        window_start = now - self.window_seconds

        with self._lock:
            # 1. IP Hard Cap evaluation
            ip_timestamps = self._records.get(ip_key)
            if ip_timestamps is not None:
                while ip_timestamps and ip_timestamps[0] <= window_start:
                    ip_timestamps.popleft()
                ip_count = len(ip_timestamps)
            else:
                ip_count = 0

            # 2. Fingerprint evaluation
            if fp_key != ip_key:
                fp_timestamps = self._records.get(fp_key)
                if fp_timestamps is not None:
                    while fp_timestamps and fp_timestamps[0] <= window_start:
                        fp_timestamps.popleft()
                    fp_count = len(fp_timestamps)
                else:
                    fp_count = 0
            else:
                fp_timestamps = ip_timestamps
                fp_count = ip_count

            is_ip_limited = ip_count >= ip_cap
            is_fp_limited = fp_count >= effective_limit

            if is_ip_limited or is_fp_limited:
                # Record violation in IP repeat offender tracking history
                if client_ip not in self._violation_history:
                    if len(self._violation_history) >= self.MAX_TRACKED_KEYS:
                        self._violation_history.popitem(last=False)
                    self._violation_history[client_ip] = deque()
                viol_deq = self._violation_history[client_ip]
                self._violation_history.move_to_end(client_ip)

                while viol_deq and viol_deq[0] <= (now - self.VIOLATION_WINDOW_SECONDS):
                    viol_deq.popleft()
                viol_deq.append(now)
                num_violations = len(viol_deq)

                active_key = ip_key if is_ip_limited else fp_key
                active_limit = ip_cap if is_ip_limited else effective_limit
                active_count = ip_count if is_ip_limited else fp_count
                ts_to_check = ip_timestamps if is_ip_limited else fp_timestamps

                if ts_to_check and len(ts_to_check) > 0:
                    oldest = ts_to_check[0]
                    base_retry_after = max(1, math.ceil(oldest + self.window_seconds - now))
                else:
                    base_retry_after = max(1, math.ceil(self.window_seconds))

                if num_violations >= 3:
                    multiplier = 2 ** (num_violations - 3)
                    backoff = min(self.MAX_BACKOFF_RETRY_AFTER, self.BASE_BACKOFF_RETRY_AFTER * multiplier)
                    retry_after = max(base_retry_after, backoff)
                else:
                    retry_after = base_retry_after

                return RateLimitResult(
                    is_limited=True,
                    current_count=active_count,
                    limit=active_limit,
                    remaining=0,
                    retry_after=retry_after,
                    window_seconds=self.window_seconds,
                    scope=scope,
                    client_ip=client_ip,
                    tracking_key=active_key,
                    violations_count=num_violations,
                )

            # Request allowed: update both keys in LRU order
            if ip_key not in self._records:
                if len(self._records) >= self.MAX_TRACKED_KEYS:
                    self._records.popitem(last=False)
                self._records[ip_key] = deque()
            self._records[ip_key].append(now)
            self._records.move_to_end(ip_key)

            if fp_key != ip_key:
                if fp_key not in self._records:
                    if len(self._records) >= self.MAX_TRACKED_KEYS:
                        self._records.popitem(last=False)
                    self._records[fp_key] = deque()
                self._records[fp_key].append(now)
                self._records.move_to_end(fp_key)

            remaining_fp = max(0, effective_limit - len(self._records[fp_key]))
            remaining_ip = max(0, ip_cap - len(self._records[ip_key]))
            remaining = min(remaining_fp, remaining_ip)

            if client_ip in self._violation_history:
                viol_deq = self._violation_history[client_ip]
                while viol_deq and viol_deq[0] <= (now - self.VIOLATION_WINDOW_SECONDS):
                    viol_deq.popleft()

            return RateLimitResult(
                is_limited=False,
                current_count=len(self._records[fp_key]),
                limit=effective_limit,
                remaining=remaining,
                retry_after=0,
                window_seconds=self.window_seconds,
                scope=scope,
                client_ip=client_ip,
                tracking_key=fp_key,
                violations_count=len(self._violation_history.get(client_ip, [])),
            )

    def reset(self, client_ip: str | None = None) -> None:
        """Resets rate limit records and violation history for all or a specific client IP."""
        with self._lock:
            if client_ip is None:
                self._records.clear()
                self._violation_history.clear()
            else:
                keys_to_remove = [
                    k for k in self._records
                    if k.startswith(f"{client_ip}:") or k.startswith(f"{client_ip}::")
                ]
                for k in keys_to_remove:
                    del self._records[k]
                self._violation_history.pop(client_ip, None)

    def cleanup_expired_records(self, max_idle_seconds: float = 300.0, now: float | None = None) -> int:
        """Evicts stale IP keys and old violation histories from RAM to prevent memory accumulation."""
        if now is None:
            now = time.time()
        expiry_boundary = now - max_idle_seconds
        viol_boundary = now - self.VIOLATION_WINDOW_SECONDS
        removed_count = 0

        with self._lock:
            keys_to_delete = []
            for key, timestamps in list(self._records.items()):
                while timestamps and timestamps[0] <= (now - self.window_seconds):
                    timestamps.popleft()
                if not timestamps or timestamps[-1] < expiry_boundary:
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del self._records[key]
                removed_count += 1

            viol_keys_to_delete = []
            for ip, viol_deq in list(self._violation_history.items()):
                while viol_deq and viol_deq[0] <= viol_boundary:
                    viol_deq.popleft()
                if not viol_deq:
                    viol_keys_to_delete.append(ip)

            for ip in viol_keys_to_delete:
                del self._violation_history[ip]

        return removed_count
