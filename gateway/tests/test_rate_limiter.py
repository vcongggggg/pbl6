import concurrent.futures

from app.security.rate_limiter import SlidingWindowRateLimiter


def test_rate_limiter_basic_allowing_and_remaining():
    """Verifies that initial requests are allowed and remaining count decreases."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=5)
    ip = "192.168.1.50"

    res1 = limiter.check_rate_limit(ip, "/api/products")
    assert res1.is_limited is False
    assert res1.current_count == 1
    assert res1.limit == 5
    assert res1.remaining == 4
    assert res1.scope == "global"

    res2 = limiter.check_rate_limit(ip, "/api/products")
    assert res2.is_limited is False
    assert res2.current_count == 2
    assert res2.remaining == 3


def test_rate_limiter_blocks_when_limit_exceeded():
    """Verifies that exceeding the limit blocks with is_limited=True and positive retry_after."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=3)
    ip = "10.0.0.1"

    # Send 3 allowed requests
    for _ in range(3):
        res = limiter.check_rate_limit(ip, "/test")
        assert res.is_limited is False

    # 4th request must be rate limited
    blocked_res = limiter.check_rate_limit(ip, "/test")
    assert blocked_res.is_limited is True
    assert blocked_res.current_count == 3
    assert blocked_res.remaining == 0
    assert blocked_res.retry_after > 0
    assert blocked_res.retry_after <= 60


def test_rate_limiter_scope_resolution():
    """Verifies that sensitive endpoints resolve to specific scopes and quotas."""
    limiter = SlidingWindowRateLimiter(
        window_seconds=60.0,
        default_limit=60,
        sensitive_limits={"auth": 10, "admin": 15, "files": 20},
    )
    ip = "172.16.0.5"

    res_auth = limiter.check_rate_limit(ip, "/api/v1/auth/login")
    assert res_auth.scope == "auth"
    assert res_auth.limit == 10

    res_admin = limiter.check_rate_limit(ip, "/admin/dashboard/ping")
    assert res_admin.scope == "admin"
    assert res_admin.limit == 15

    res_files = limiter.check_rate_limit(ip, "/static/files/report.pdf")
    assert res_files.scope == "files"
    assert res_files.limit == 20

    res_global = limiter.check_rate_limit(ip, "/rest/products/list")
    assert res_global.scope == "global"
    assert res_global.limit == 60


def test_rate_limiter_risk_penalty_halves_limit():
    """Verifies that Phase 7 risk penalty applies 50% stricter quota."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=10)
    ip = "192.168.1.99"

    # Normal check has limit 10
    normal_res = limiter.check_rate_limit(ip, "/api/search", risk_penalty=False)
    assert normal_res.limit == 10

    # Risk-penalized check has limit 5
    penalized_res = limiter.check_rate_limit(ip, "/api/search", risk_penalty=True)
    assert penalized_res.limit == 5


def test_rate_limiter_sliding_window_expiration():
    """Verifies timestamps slide out of window allowing subsequent requests."""
    limiter = SlidingWindowRateLimiter(window_seconds=10.0, default_limit=2)
    ip = "192.168.1.100"
    base_time = 1000.0

    # 2 requests at base_time
    r1 = limiter.check_rate_limit(ip, "/test", now=base_time)
    assert r1.is_limited is False
    r2 = limiter.check_rate_limit(ip, "/test", now=base_time + 1.0)
    assert r2.is_limited is False

    # 3rd request at base_time + 2.0 is blocked
    r3 = limiter.check_rate_limit(ip, "/test", now=base_time + 2.0)
    assert r3.is_limited is True

    # Fast forward past window (base_time + 12.0) -> first timestamp evicted
    r4 = limiter.check_rate_limit(ip, "/test", now=base_time + 12.0)
    assert r4.is_limited is False


def test_rate_limiter_reset():
    """Verifies that reset clears rate limits for specific or all IPs."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=1)
    ip1 = "1.1.1.1"
    ip2 = "2.2.2.2"

    limiter.check_rate_limit(ip1, "/api")
    limiter.check_rate_limit(ip2, "/api")
    assert limiter.check_rate_limit(ip1, "/api").is_limited is True
    assert limiter.check_rate_limit(ip2, "/api").is_limited is True

    # Reset specific IP
    limiter.reset(ip1)
    assert limiter.check_rate_limit(ip1, "/api").is_limited is False
    assert limiter.check_rate_limit(ip2, "/api").is_limited is True

    # Reset all
    limiter.reset()
    assert limiter.check_rate_limit(ip2, "/api").is_limited is False


def test_rate_limiter_cleanup_expired_records():
    """Verifies cleanup_expired_records purges idle records from RAM."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=5)
    now = 5000.0

    limiter.check_rate_limit("10.0.0.1", "/api", now=now - 500.0)
    limiter.check_rate_limit("10.0.0.2", "/api", now=now - 10.0)

    # 10.0.0.1 was idle for 500s > max_idle 300s -> should be removed
    removed = limiter.cleanup_expired_records(max_idle_seconds=300.0, now=now)
    assert removed >= 1


def test_rate_limiter_thread_safety():
    """Verifies that sliding window counter handles concurrent threads safely."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=100)
    ip = "192.168.1.200"

    def record_hit():
        return limiter.check_rate_limit(ip, "/concurrent")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(record_hit) for _ in range(50)]
        results = [f.result() for f in futures]

    assert len(results) == 50
    assert all(not r.is_limited for r in results)
    final_res = limiter.check_rate_limit(ip, "/concurrent")
    assert final_res.current_count == 51


def test_exponential_backoff_after_multiple_violations():
    """Verifies that repeat offenders trigger exponential backoff (120s, 240s, 480s, max 900s)."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=2)
    ip = "192.168.1.77"
    base_time = 1000.0

    # Fill quota (2 requests)
    assert limiter.check_rate_limit(ip, "/api", now=base_time).is_limited is False
    assert limiter.check_rate_limit(ip, "/api", now=base_time + 1.0).is_limited is False

    # Violation 1: normal retry-after
    v1 = limiter.check_rate_limit(ip, "/api", now=base_time + 2.0)
    assert v1.is_limited is True
    assert v1.violations_count == 1
    assert v1.retry_after <= 60

    # Violation 2: normal retry-after
    v2 = limiter.check_rate_limit(ip, "/api", now=base_time + 3.0)
    assert v2.is_limited is True
    assert v2.violations_count == 2
    assert v2.retry_after <= 60

    # Violation 3: 1st tier exponential backoff (120s)
    v3 = limiter.check_rate_limit(ip, "/api", now=base_time + 4.0)
    assert v3.is_limited is True
    assert v3.violations_count == 3
    assert v3.retry_after >= 120

    # Violation 4: 2nd tier exponential backoff (240s)
    v4 = limiter.check_rate_limit(ip, "/api", now=base_time + 5.0)
    assert v4.is_limited is True
    assert v4.violations_count == 4
    assert v4.retry_after >= 240

    # Violation 5: 3rd tier exponential backoff (480s)
    v5 = limiter.check_rate_limit(ip, "/api", now=base_time + 6.0)
    assert v5.is_limited is True
    assert v5.violations_count == 5
    assert v5.retry_after >= 480

    # Violation 6: max penalty cap (900s)
    v6 = limiter.check_rate_limit(ip, "/api", now=base_time + 7.0)
    assert v6.is_limited is True
    assert v6.violations_count == 6
    assert v6.retry_after == 900


def test_session_aware_scoping_separates_clients_on_same_ip():
    """Verifies that different sessions or user agents on the same NAT IP do not throttle each other."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=2)
    shared_ip = "203.0.113.10"
    base_time = 2000.0

    # Client Alice with session token
    assert (
        limiter.check_rate_limit(
            shared_ip,
            "/api",
            session_id="token_alice",
            user_agent="Browser-A",
            now=base_time,
        ).is_limited
        is False
    )
    assert (
        limiter.check_rate_limit(
            shared_ip,
            "/api",
            session_id="token_alice",
            user_agent="Browser-A",
            now=base_time + 1.0,
        ).is_limited
        is False
    )

    # Alice exceeds quota
    alice_blocked = limiter.check_rate_limit(
        shared_ip,
        "/api",
        session_id="token_alice",
        user_agent="Browser-A",
        now=base_time + 2.0,
    )
    assert alice_blocked.is_limited is True

    # Client Bob on SAME IP with different session must NOT be throttled
    bob_res = limiter.check_rate_limit(
        shared_ip,
        "/api",
        session_id="token_bob",
        user_agent="Browser-B",
        now=base_time + 2.5,
    )
    assert bob_res.is_limited is False
    assert bob_res.remaining == 1

    # Client Charlie on SAME IP without session but with distinct User-Agent must NOT be throttled
    charlie_res = limiter.check_rate_limit(
        shared_ip,
        "/api",
        user_agent="MobileApp-Charlie",
        now=base_time + 3.0,
    )
    assert charlie_res.is_limited is False
    assert charlie_res.remaining == 1


def test_violation_history_cleanup_after_window():
    """Verifies that expired violation histories (> 600s) are purged during cleanup."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=1)
    ip = "192.168.100.99"
    now = 10000.0

    # Exceed limit to create violation entry
    limiter.check_rate_limit(ip, "/api", now=now - 700.0)
    limiter.check_rate_limit(ip, "/api", now=now - 650.0)

    # Clean up at current time (both violations are > 600s old)
    removed = limiter.cleanup_expired_records(max_idle_seconds=300.0, now=now)
    assert removed >= 1
    assert ip not in limiter._violation_history
