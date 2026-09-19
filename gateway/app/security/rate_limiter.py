import math
import threading
import time
from collections import defaultdict, deque
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
        }


class SlidingWindowRateLimiter:
    """In-memory thread-safe sliding window rate limiter.

    Implements O(1) sliding window eviction using timestamp deques in RAM.
    Conforms to:
      - OWASP API Security Top 10 (2023) - API4:2023 Unrestricted Resource Consumption
      - OWASP ModSecurity CRS v4.0 HTTP Flood & Brute-force Defense
      - NIST SP 800-115 Automated Attack Mitigation & HTTP 429 Retry-After
    """

    DEFAULT_WINDOW_SECONDS: float = 60.0
    DEFAULT_GLOBAL_LIMIT: int = 60
    DEFAULT_SENSITIVE_LIMITS: dict[str, int] = {
        "auth": 10,       # Max 10 login attempts per minute (Brute-force protection)
        "admin": 15,      # Max 15 admin operations per minute
        "files": 20,      # Max 20 file downloads per minute
    }

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
        self._records: dict[str, deque[float]] = defaultdict(deque)
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

    def check_rate_limit(
        self,
        client_ip: str,
        path: str = "",
        risk_penalty: bool = False,
        custom_limit: int | None = None,
        now: float | None = None,
    ) -> RateLimitResult:
        """Checks whether the client IP has exceeded the allowed request frequency.

        Args:
            client_ip: Client's remote IP address.
            path: Target request path.
            risk_penalty: If True (e.g. from Phase 7 RATE_LIMIT score 60-80),
                          applies 50% stricter quota to the client.
            custom_limit: Optional override for rate limit quota.
            now: Optional timestamp override for deterministic testing.
        """
        if now is None:
            now = time.time()

        scope = self.resolve_scope(path)
        base_limit = custom_limit if custom_limit is not None else self.sensitive_limits.get(scope, self.default_limit)

        # Apply risk penalty if flagged by Decision Engine
        if risk_penalty:
            effective_limit = max(1, base_limit // 2)
        else:
            effective_limit = max(1, base_limit)

        key = f"{client_ip}:{scope}"
        window_start = now - self.window_seconds

        with self._lock:
            timestamps = self._records[key]

            # 1. Evict expired timestamps older than window_start
            while timestamps and timestamps[0] <= window_start:
                timestamps.popleft()

            current_count = len(timestamps)

            # 2. Check threshold
            if current_count >= effective_limit:
                # Rate limit exceeded: calculate retry-after based on oldest timestamp in window
                oldest = timestamps[0]
                retry_after = max(1, math.ceil(oldest + self.window_seconds - now))
                return RateLimitResult(
                    is_limited=True,
                    current_count=current_count,
                    limit=effective_limit,
                    remaining=0,
                    retry_after=retry_after,
                    window_seconds=self.window_seconds,
                    scope=scope,
                    client_ip=client_ip,
                )

            # 3. Allow request: record current timestamp
            timestamps.append(now)
            remaining = max(0, effective_limit - len(timestamps))

            return RateLimitResult(
                is_limited=False,
                current_count=len(timestamps),
                limit=effective_limit,
                remaining=remaining,
                retry_after=0,
                window_seconds=self.window_seconds,
                scope=scope,
                client_ip=client_ip,
            )

    def reset(self, client_ip: str | None = None) -> None:
        """Resets rate limit records for all or a specific client IP."""
        with self._lock:
            if client_ip is None:
                self._records.clear()
            else:
                keys_to_remove = [k for k in self._records if k.startswith(f"{client_ip}:")]
                for k in keys_to_remove:
                    del self._records[k]

    def cleanup_expired_records(self, max_idle_seconds: float = 300.0, now: float | None = None) -> int:
        """Evicts stale IP keys from RAM to prevent memory accumulation."""
        if now is None:
            now = time.time()
        expiry_boundary = now - max_idle_seconds
        removed_count = 0

        with self._lock:
            keys_to_delete = []
            for key, timestamps in self._records.items():
                while timestamps and timestamps[0] <= (now - self.window_seconds):
                    timestamps.popleft()
                if not timestamps or timestamps[-1] < expiry_boundary:
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del self._records[key]
                removed_count += 1

        return removed_count
