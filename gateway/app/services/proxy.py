import logging
import time

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from app.core.config import Settings

logger = logging.getLogger("waf.gateway.proxy")

# Hop-by-hop headers that must not be forwarded between client and upstream
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

# Sensitive Gateway-only headers that must never leak to upstream Target API (SEC-PBL6-007)
SENSITIVE_GATEWAY_HEADERS = {
    "x-api-key",
}


def filter_request_headers(
    request_headers: dict[str, str] | list[tuple[str, str]],
) -> dict[str, str]:
    """Strip hop-by-hop and sensitive Gateway-only headers (e.g. X-API-Key) before upstream forward."""
    header_dict = dict(request_headers) if isinstance(request_headers, list) else request_headers
    blocked = HOP_BY_HOP_HEADERS | SENSITIVE_GATEWAY_HEADERS
    filtered: dict[str, str] = {}
    for key, value in header_dict.items():
        if key.lower() not in blocked:
            filtered[key] = value
    return filtered


def filter_response_headers(upstream_headers: httpx.Headers) -> dict[str, str]:
    """Strip hop-by-hop response headers (single-value dict helper for backward compatibility)."""
    filtered: dict[str, str] = {}
    for key, value in upstream_headers.items():
        if key.lower() not in HOP_BY_HOP_HEADERS:
            filtered[key] = value
    return filtered


def filter_response_header_items(upstream_headers: httpx.Headers) -> list[tuple[str, str]]:
    """Strip hop-by-hop response headers while preserving multi-value headers like Set-Cookie (SEC-PBL6-007)."""
    items: list[tuple[str, str]] = []
    for key, value in upstream_headers.multi_items():
        if key.lower() not in HOP_BY_HOP_HEADERS:
            items.append((key, value))
    return items


class ProxyService:
    """Handles reverse proxying requests to the upstream Target Web API."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        self.settings = settings
        self._client = client

    def get_client(self) -> httpx.AsyncClient:
        """Returns or creates the AsyncClient with configured timeouts."""
        if self._client is not None:
            return self._client
        return httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=self.settings.proxy_timeout_connect,
                read=self.settings.proxy_timeout_read,
                write=self.settings.proxy_timeout_write,
                pool=self.settings.proxy_timeout_pool,
            ),
            follow_redirects=False,
        )

    async def forward(
        self,
        request: Request,
        path: str,
        request_id: str,
        body_bytes: bytes,
    ) -> tuple[Response, float, int]:
        """Forward an incoming HTTP request to the configured target API.

        Returns:
            tuple[Response, response_time_ms, response_size]
        """
        # Strict target URL construction (Prevents Open Proxy / SSRF)
        target_base = self.settings.target_api_url.rstrip("/")
        target_path = path.lstrip("/")
        target_url = f"{target_base}/{target_path}"

        query_params = str(request.url.query) if request.url.query else None
        if query_params:
            target_url = f"{target_url}?{query_params}"

        forward_headers = filter_request_headers(dict(request.headers))
        forward_headers["X-Request-ID"] = request_id

        close_client = self._client is None
        client = self.get_client()
        start_time = time.perf_counter()

        try:
            upstream_response = await client.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                content=body_bytes if body_bytes else None,
            )

            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            response_content = upstream_response.content
            response_size = len(response_content)

            response = Response(
                content=response_content,
                status_code=upstream_response.status_code,
            )
            for key, value in filter_response_header_items(upstream_response.headers):
                response.headers.append(key, value)
            response.headers["X-Request-ID"] = request_id
            return response, latency_ms, response_size

        except (httpx.ConnectError, httpx.NetworkError) as err:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            logger.warning(f"Upstream target unavailable [{request_id}]: {err}")
            error_payload = {
                "status": "error",
                "error": {
                    "code": "TARGET_UNAVAILABLE",
                    "message": "The upstream target service is currently unreachable.",
                },
            }
            resp = JSONResponse(
                status_code=502,
                content=error_payload,
                headers={"X-Request-ID": request_id},
            )
            return resp, latency_ms, len(resp.body)

        except httpx.TimeoutException as err:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            logger.warning(f"Upstream target timeout [{request_id}]: {err}")
            error_payload = {
                "status": "error",
                "error": {
                    "code": "GATEWAY_TIMEOUT",
                    "message": "The upstream target service timed out.",
                },
            }
            resp = JSONResponse(
                status_code=504,
                content=error_payload,
                headers={"X-Request-ID": request_id},
            )
            return resp, latency_ms, len(resp.body)

        except Exception as err:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            logger.error(f"Upstream proxy internal error [{request_id}]: {err}")
            error_payload = {
                "status": "error",
                "error": {
                    "code": "BAD_GATEWAY",
                    "message": (
                        "An unexpected error occurred while proxying to the upstream service."
                    ),
                },
            }
            resp = JSONResponse(
                status_code=502,
                content=error_payload,
                headers={"X-Request-ID": request_id},
            )
            return resp, latency_ms, len(resp.body)
        finally:
            if close_client:
                await client.aclose()
