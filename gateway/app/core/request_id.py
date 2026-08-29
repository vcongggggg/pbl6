import re
import uuid

REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def resolve_request_id(incoming_header: str | None) -> str:
    """Validate and return incoming X-Request-ID or generate a new safe UUID4 hex."""
    if incoming_header and REQUEST_ID_REGEX.match(incoming_header):
        return incoming_header
    return uuid.uuid4().hex
