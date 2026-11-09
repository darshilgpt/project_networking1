"""HTTP Protocol Inspector for stream-based and message-delimited HTTP dissection."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import logging
import re
import time
from typing import Deque, Dict, List, Optional, Tuple
import urllib.parse

from reassembly.tcp_reassembler import DirectionalTCPStream, PendingRequest, TrafficDirection

logger = logging.getLogger("dpi_ids_ips.dpi.http_inspector")

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}


def decode_url_bounded(text: str, max_iterations: int = 3) -> str:
    """
    Applies bounded iterative URL-decoding to resolve repeated percent-encoding safely.
    E.g. '%252e%252e%252f' -> '%2e%2e%2f' -> '../'
    """
    if not text:
        return ""
    current = text
    for _ in range(max_iterations):
        try:
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
        except Exception:
            break
    return current


@dataclass
class HTTPMetadata:
    """Extracted and normalized HTTP message fields."""
    # Existing fields (100% backward compatible)
    is_request: bool
    method: Optional[str] = None
    uri: Optional[str] = None
    version: Optional[str] = None
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    host: Optional[str] = None
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    body_preview: str = ""

    # Phase 3 stream and framing enhancements
    message_id: str = ""
    raw_uri: str = ""
    normalized_uri: str = ""
    raw_query: str = ""
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    normalized_query_params: Dict[str, List[str]] = field(default_factory=dict)
    raw_body: bytes = b""
    normalized_body: str = ""
    framing_method: str = "NONE"  # CONTENT_LENGTH, CHUNKED, NO_BODY, CLOSE_DELIMITED, AMBIGUOUS
    is_chunked: bool = False
    is_truncated: bool = False
    truncation_reason: Optional[str] = None
    is_complete: bool = True


class HTTPMessageStreamParser:
    """
    Stateful streaming HTTP parser framing complete messages from continuous directional TCP streams.
    Implements RFC 9112 framing, chunked transfer decoding, and request-response correlation.
    """

    MAX_HEADER_SIZE = 16 * 1024       # 16 KB header limit
    MAX_BODY_INSPECT_SIZE = 64 * 1024 # 64 KB inspected body preview limit

    @classmethod
    def decode_chunked_body(cls, data: bytes) -> Tuple[bytes, bool, int]:
        """
        Decodes HTTP chunked transfer encoding (RFC 9112 Section 7.1).

        Returns:
            Tuple of (decoded_body, is_complete, total_consumed_bytes)
        """
        decoded = bytearray()
        idx = 0
        total_len = len(data)

        while idx < total_len:
            # Look for CRLF ending the chunk header line
            line_end = data.find(b"\r\n", idx)
            if line_end == -1:
                return bytes(decoded), False, idx

            chunk_header = data[idx:line_end].strip()
            # Split chunk extensions if present (e.g. "1a;ext=foo")
            chunk_size_str = chunk_header.split(b";")[0].strip()

            try:
                chunk_len = int(chunk_size_str, 16)
            except ValueError:
                # Malformed chunk size
                return bytes(decoded), True, line_end + 2

            # Terminal chunk: size 0
            if chunk_len == 0:
                # Check for terminating CRLF after trailers
                trailer_end = data.find(b"\r\n\r\n", idx)
                if trailer_end != -1:
                    return bytes(decoded), True, trailer_end + 4
                elif data.find(b"\r\n", line_end + 2) == line_end + 2:
                    return bytes(decoded), True, line_end + 4
                else:
                    return bytes(decoded), False, idx

            chunk_start = line_end + 2
            chunk_end = chunk_start + chunk_len
            if chunk_end + 2 > total_len:
                # Chunk payload not yet fully received
                return bytes(decoded), False, idx

            # Ensure trailing CRLF exists after chunk data
            decoded.extend(data[chunk_start:chunk_end])
            idx = chunk_end + 2

        return bytes(decoded), False, idx

    @classmethod
    def parse_messages(
        cls,
        stream_bytes: bytes,
        direction: TrafficDirection,
        pending_requests: Optional[Deque[PendingRequest]] = None,
        is_connection_closed: bool = False,
        termination_type: Optional[str] = None,
        stream_id_prefix: str = "stream",
    ) -> Tuple[List[HTTPMetadata], int]:
        """
        Frames and extracts all complete HTTP messages available in stream_bytes.

        Args:
            stream_bytes: Unconsumed reassembled bytes in this direction.
            direction: CLIENT_TO_SERVER, SERVER_TO_CLIENT, or UNKNOWN.
            pending_requests: Correlation queue for matching responses with requests.
            is_connection_closed: Whether FIN has been received on this stream.
            termination_type: "FIN" or "RST".
            stream_id_prefix: Prefix for unique message IDs.

        Returns:
            Tuple of (list_of_parsed_HTTPMetadata, total_bytes_consumed)
        """
        messages: List[HTTPMetadata] = []
        offset = 0
        total_len = len(stream_bytes)
        msg_seq = 0

        while offset < total_len:
            curr_data = stream_bytes[offset:]

            # 1. Search for end of headers
            hdr_end = curr_data.find(b"\r\n\r\n")
            delim_len = 4
            if hdr_end == -1:
                hdr_end = curr_data.find(b"\n\n")
                delim_len = 2

            if hdr_end == -1:
                # Headers incomplete; check maximum header size bound
                if len(curr_data) > cls.MAX_HEADER_SIZE:
                    logger.warning("HTTP header exceeded maximum size limit (%d bytes).", cls.MAX_HEADER_SIZE)
                    meta = HTTPMetadata(
                        is_request=(direction == TrafficDirection.CLIENT_TO_SERVER),
                        message_id=f"{stream_id_prefix}_{msg_seq}",
                        is_truncated=True,
                        truncation_reason="HEADER_SIZE_LIMIT_EXCEEDED",
                        is_complete=False,
                    )
                    messages.append(meta)
                    # Advance past oversized data to recover
                    offset += len(curr_data)
                break

            header_bytes = curr_data[:hdr_end]
            body_start = hdr_end + delim_len

            try:
                header_text = header_bytes.decode("iso-8859-1")
            except Exception:
                header_text = header_bytes.decode("utf-8", errors="ignore")

            lines = header_text.splitlines()
            if not lines:
                offset += body_start
                continue

            first_line = lines[0].strip()
            parts = first_line.split(" ", 2)
            if len(parts) < 2:
                # Malformed start line; skip to prevent hanging
                offset += body_start
                continue

            is_request = False
            method = None
            uri = None
            version = None
            status_code = None
            reason_phrase = None

            # Guard against midstream desynchronization interpreting arbitrary text as HTTP
            first_token = parts[0].upper()
            if first_token in HTTP_METHODS:
                # Verify that second token is a plausible URI and version is present
                if len(parts) >= 3 and (parts[2].startswith("HTTP/1.") or parts[2].startswith("HTTP/2") or parts[2].startswith("HTTP/0.9")):
                    is_request = True
                    method = first_token
                    uri = parts[1]
                    version = parts[2]
                elif len(parts) == 2 and parts[1].startswith("/"):
                    is_request = True
                    method = first_token
                    uri = parts[1]
                    version = "HTTP/1.1"
                else:
                    offset += 1
                    continue
            elif parts[0].startswith("HTTP/"):
                if parts[1].isdigit() and len(parts[1]) == 3:
                    is_request = False
                    version = parts[0]
                    status_code = int(parts[1])
                    if len(parts) > 2:
                        reason_phrase = parts[2]
                else:
                    offset += 1
                    continue
            else:
                # Not a valid HTTP start line; advance by 1 byte to realign
                offset += 1
                continue

            # Parse headers into normalized lowercase dict
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k_clean = k.strip().lower()
                    if k_clean in headers:
                        # Append multiple values per RFC 9110
                        headers[k_clean] += f", {v.strip()}"
                    else:
                        headers[k_clean] = v.strip()

            host = headers.get("host")
            user_agent = headers.get("user-agent")
            content_type = headers.get("content-type")

            # Check framing headers
            has_chunked = "chunked" in headers.get("transfer-encoding", "").lower()
            content_length = None
            framing_method = "NONE"
            raw_cl = headers.get("content-length")
            if raw_cl:
                # Handle comma-separated multiple Content-Length headers safely
                cl_parts = [p.strip() for p in raw_cl.split(",") if p.strip()]
                if cl_parts and all(p.isdigit() for p in cl_parts):
                    if len(set(cl_parts)) > 1:
                        # Conflicting multiple Content-Length headers (RFC 9112 Section 6.3)
                        framing_method = "AMBIGUOUS_CONTENT_LENGTH"
                        content_length = int(cl_parts[0])
                    else:
                        # Identical duplicate Content-Length headers (RFC 9112 allows if all identical)
                        content_length = int(cl_parts[0])
                        framing_method = "CONTENT_LENGTH"

            # Transfer-Encoding combined with Content-Length (RFC 9112 Section 6.1)
            # Transfer-Encoding MUST override Content-Length; flag ambiguous
            if has_chunked and raw_cl:
                framing_method = "AMBIGUOUS_TRANSFER_ENCODING_AND_CONTENT_LENGTH"

            # Determine framing method and body boundaries
            body_bytes = b""
            consumed_for_msg = 0
            is_complete = False
            is_truncated = False
            truncation_reason = None

            if is_request:
                # --- Request Framing (RFC 9112 Section 6) ---
                if has_chunked:
                    if framing_method == "NONE":
                        framing_method = "CHUNKED"
                    decoded_chunked, chunked_done, chunked_consumed = cls.decode_chunked_body(curr_data[body_start:])
                    if not chunked_done:
                        break  # Incomplete chunked request; wait for remaining packets
                    body_bytes = decoded_chunked
                    consumed_for_msg = body_start + chunked_consumed
                    is_complete = True

                elif content_length is not None:
                    if framing_method == "NONE":
                        framing_method = "CONTENT_LENGTH"
                    if len(curr_data) - body_start < content_length:
                        break  # Incomplete body; wait for more TCP segments
                    body_bytes = curr_data[body_start : body_start + content_length]
                    consumed_for_msg = body_start + content_length
                    is_complete = True

                else:
                    # Requests without Transfer-Encoding or Content-Length have NO body
                    framing_method = "NO_BODY"
                    body_bytes = b""
                    consumed_for_msg = body_start
                    is_complete = True

                # Correlate request in pending_requests queue for response framing
                if is_complete and pending_requests is not None:
                    pending_requests.append(
                        PendingRequest(
                            method=method or "GET",
                            uri=uri or "/",
                            timestamp=time.time(),
                            seq_index=msg_seq,
                        )
                    )

            else:
                # --- Response Framing (RFC 9112 Section 6.3) ---
                # Check correlated request method
                correlated_method = None
                if pending_requests and len(pending_requests) > 0:
                    correlated_method = pending_requests[0].method

                # 1. Status codes 1xx, 204, 304 have no body (RFC 9112 Section 6.3)
                if status_code is not None and (100 <= status_code < 200 or status_code in (204, 304)):
                    framing_method = f"STATUS_{status_code}_NO_BODY"
                    body_bytes = b""
                    consumed_for_msg = body_start
                    is_complete = True
                    # Only pop pending request if it was NOT a 1xx informational response
                    if not (100 <= status_code < 200) and pending_requests:
                        pending_requests.popleft()

                # 2. Responses to HEAD have no body regardless of Content-Length
                elif correlated_method == "HEAD":
                    framing_method = "HEAD_RESPONSE"
                    body_bytes = b""
                    consumed_for_msg = body_start
                    is_complete = True
                    if pending_requests:
                        pending_requests.popleft()

                # 3. Chunked transfer encoding
                elif has_chunked:
                    framing_method = "CHUNKED"
                    decoded_chunked, chunked_done, chunked_consumed = cls.decode_chunked_body(curr_data[body_start:])
                    if not chunked_done:
                        break
                    body_bytes = decoded_chunked
                    consumed_for_msg = body_start + chunked_consumed
                    is_complete = True
                    if pending_requests:
                        pending_requests.popleft()

                # 4. Content-Length
                elif content_length is not None:
                    framing_method = "CONTENT_LENGTH"
                    if len(curr_data) - body_start < content_length:
                        break
                    body_bytes = curr_data[body_start : body_start + content_length]
                    consumed_for_msg = body_start + content_length
                    is_complete = True
                    if pending_requests:
                        pending_requests.popleft()

                # 5. Connection: close delimited responses
                elif is_connection_closed:
                    if termination_type == "RST":
                        # Connection was abruptly aborted by RST; do not treat as clean response
                        framing_method = "ABORTED_RESET"
                        is_complete = False
                        is_truncated = True
                        truncation_reason = "CONNECTION_RESET"
                        consumed_for_msg = len(curr_data)
                    else:
                        framing_method = "CLOSE_DELIMITED"
                        body_bytes = curr_data[body_start:]
                        consumed_for_msg = len(curr_data)
                        is_complete = True
                        if pending_requests:
                            pending_requests.popleft()
                else:
                    # Response body continues until connection close; wait for FIN or more data
                    break

            if not is_complete:
                break

            # Body truncation guard
            raw_body_len = len(body_bytes)
            if raw_body_len > cls.MAX_BODY_INSPECT_SIZE:
                is_truncated = True
                truncation_reason = f"BODY_EXCEEDED_LIMIT ({raw_body_len} > {cls.MAX_BODY_INSPECT_SIZE})"
                body_bytes = body_bytes[: cls.MAX_BODY_INSPECT_SIZE]

            # URL and Query Parameter Extraction
            raw_uri = uri or ""
            normalized_uri = decode_url_bounded(raw_uri, max_iterations=3)
            raw_query = ""
            query_params: Dict[str, List[str]] = {}
            normalized_query_params: Dict[str, List[str]] = {}

            if "?" in raw_uri:
                raw_query = raw_uri.split("?", 1)[1]
                query_params = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
                for qk, qvals in query_params.items():
                    norm_k = decode_url_bounded(qk, max_iterations=3)
                    norm_vals = [decode_url_bounded(v, max_iterations=3) for v in qvals]
                    normalized_query_params[norm_k] = norm_vals

            # Body preview and normalization
            body_preview = body_bytes[:256].decode("utf-8", errors="replace") if body_bytes else ""
            normalized_body = decode_url_bounded(
                body_bytes.decode("utf-8", errors="replace"), max_iterations=2
            ) if body_bytes else ""

            msg_seq += 1
            meta = HTTPMetadata(
                is_request=is_request,
                method=method,
                uri=raw_uri,
                version=version,
                status_code=status_code,
                reason_phrase=reason_phrase,
                headers=headers,
                host=host,
                user_agent=user_agent,
                content_type=content_type,
                content_length=content_length,
                body_preview=body_preview,
                message_id=f"{stream_id_prefix}_{msg_seq}",
                raw_uri=raw_uri,
                normalized_uri=normalized_uri,
                raw_query=raw_query,
                query_params=query_params,
                normalized_query_params=normalized_query_params,
                raw_body=body_bytes,
                normalized_body=normalized_body,
                framing_method=framing_method,
                is_chunked=has_chunked,
                is_truncated=is_truncated,
                truncation_reason=truncation_reason,
                is_complete=is_complete,
            )
            messages.append(meta)
            offset += consumed_for_msg

        return messages, offset


class HTTPInspector:
    """Inspects and dissects HTTP/1.0 and HTTP/1.1 traffic from packets or streams."""

    @classmethod
    def is_http(cls, payload: bytes) -> bool:
        """Determines if the payload begins with a valid HTTP method or HTTP status line."""
        if len(payload) < 4:
            return False

        first_token = payload.split(b" ", 1)[0].decode("ascii", errors="ignore").upper()
        if first_token in HTTP_METHODS:
            return True

        if payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2"):
            return True

        return False

    @classmethod
    def inspect(cls, payload: bytes) -> Optional[HTTPMetadata]:
        """
        Backward-compatible single-payload parser returning the first HTTP message metadata.
        """
        if not cls.is_http(payload):
            return None

        messages, _ = HTTPMessageStreamParser.parse_messages(
            stream_bytes=payload,
            direction=TrafficDirection.UNKNOWN,
            is_connection_closed=True,
            stream_id_prefix="single_payload",
        )
        return messages[0] if messages else None


