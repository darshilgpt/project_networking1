"""Main DPI Engine coordinating protocol identification, inspection, and rule matching."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

from dpi.dns_inspector import DNSInspector, DNSMetadata
from dpi.http_inspector import HTTPInspector, HTTPMetadata, HTTPMessageStreamParser
from dpi.protocol_detector import ProtocolDetector
from dpi.signature_matcher import SignatureMatcher
from dpi.tls_inspector import TLSInspector, TLSMetadata
from models.alert_model import DPIResult
from models.flow_model import Flow
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.dpi.dpi_engine")


class DPIEngine:
    """Performs deep inspection of application payloads and TCP reassembled streams."""

    def __init__(self, matcher: Optional[SignatureMatcher] = None) -> None:
        self.matcher = matcher or SignatureMatcher()
        self.total_inspections = 0
        self.total_payload_bytes = 0
        self.signature_matches_count = 0
        self.protocol_counts: Dict[str, int] = {}

    def inspect(
        self,
        packet: ParsedPacket,
        flow: Optional[Flow] = None,
        reassembled_payload: Optional[bytes] = None,
        directional_stream: Optional[Any] = None,
        direction: Any = None,
        pending_requests: Optional[Any] = None,
    ) -> DPIResult:
        """
        Deeply inspects packet, reassembled stream, or stateful directional stream.

        Args:
            packet: ParsedPacket from Phase 1.
            flow: Associated Flow instance.
            reassembled_payload: Reassembled TCP data bytes if available.
            directional_stream: Optional DirectionalTCPStream instance.
            direction: TrafficDirection (CLIENT_TO_SERVER, SERVER_TO_CLIENT, UNKNOWN).
            pending_requests: Correlation queue for matching HTTP responses.

        Returns:
            DPIResult containing classified protocol, extracted metadata, and rule matches.
        """
        flow_id = flow.flow_id if flow else None
        
        # Determine payload to inspect
        unconsumed_stream = b""
        if directional_stream is not None:
            # Check 30s timeout on incomplete pending message bytes
            directional_stream.check_incomplete_timeout()
            unconsumed_stream = directional_stream.get_unconsumed_bytes()

        payload = unconsumed_stream if unconsumed_stream else (
            reassembled_payload if reassembled_payload is not None else packet.payload
        )
        is_reassembled = directional_stream is not None or reassembled_payload is not None

        self.total_inspections += 1
        self.total_payload_bytes += len(payload)

        result = DPIResult(
            flow_id=flow_id,
            reconstructed_stream=is_reassembled,
            stream_length=len(payload),
        )

        if not payload:
            result.protocol = "None"
            return result

        # 1. Identify Application Protocol
        detected_proto = ProtocolDetector.detect(payload, packet)
        result.protocol = detected_proto
        self.protocol_counts[detected_proto] = self.protocol_counts.get(detected_proto, 0) + 1

        fields: Dict[str, Any] = {}

        # 2. Protocol-Specific Deep Inspection
        try:
            if detected_proto == "HTTP":
                if directional_stream is not None:
                    # Stateful stream message framing
                    is_closed = directional_stream.is_terminated
                    term_type = getattr(directional_stream, "termination_type", None)
                    flow_prefix = f"flow_{flow_id or 'anon'}_{direction}"
                    
                    messages, consumed_len = HTTPMessageStreamParser.parse_messages(
                        stream_bytes=unconsumed_stream,
                        direction=direction,
                        pending_requests=pending_requests,
                        is_connection_closed=is_closed,
                        termination_type=term_type,
                        stream_id_prefix=flow_prefix,
                    )

                    if messages:
                        result.metadata["http_messages"] = messages
                        latest_msg = messages[-1]
                        result.metadata["http"] = latest_msg
                        directional_stream.advance_consumed(consumed_len)

                        # Match each new message against signature rules
                        all_matches = []
                        for msg in messages:
                            # Do not generate normal DPI signature detections if message framing is incomplete or uncertain
                            if not msg.is_complete or msg.is_truncated and msg.truncation_reason == "STREAM_BUFFER_LIMIT_EXCEEDED":
                                continue

                            # Message-level alert deduplication check
                            if msg.message_id in directional_stream.inspected_message_ids:
                                continue
                            directional_stream.inspected_message_ids.append(msg.message_id)

                            msg_fields: Dict[str, Any] = {
                                "uri": msg.normalized_uri or msg.uri or "",
                                "raw_uri": msg.raw_uri or "",
                                "method": msg.method or "",
                                "host": msg.host or "",
                                "user_agent": msg.user_agent or "",
                                "content_type": msg.content_type or "",
                                "body": msg.normalized_body or msg.body_preview,
                            }
                            msg_matches = self.matcher.match(
                                protocol="HTTP",
                                fields=msg_fields,
                                raw_payload=msg.raw_body or payload,
                            )
                            all_matches.extend(msg_matches)

                        result.matched_signatures = all_matches
                        if all_matches:
                            self.signature_matches_count += len(all_matches)
                        return result

                else:
                    http_meta = HTTPInspector.inspect(payload)
                    if http_meta:
                        result.metadata["http"] = http_meta
                        fields["uri"] = http_meta.normalized_uri or http_meta.uri or ""
                        fields["raw_uri"] = http_meta.raw_uri or ""
                        fields["method"] = http_meta.method or ""
                        fields["host"] = http_meta.host or ""
                        fields["user_agent"] = http_meta.user_agent or ""
                        fields["content_type"] = http_meta.content_type or ""
                        fields["body"] = http_meta.normalized_body or http_meta.body_preview

            elif detected_proto == "DNS":
                is_udp = packet.udp is not None
                dns_meta = DNSInspector.inspect(payload, is_udp=is_udp)
                if dns_meta:
                    result.metadata["dns"] = dns_meta
                    qnames = [q.name for q in dns_meta.questions]
                    fields["query_name"] = qnames[0] if qnames else ""
                    fields["all_queries"] = qnames
                    fields["rcode"] = dns_meta.rcode_name
                    if dns_meta.is_suspicious_domain:
                        result.metadata["dns_suspicious_reasons"] = dns_meta.suspicious_reasons

            elif detected_proto == "TLS":
                tls_meta = TLSInspector.inspect(payload)
                if tls_meta:
                    result.metadata["tls"] = tls_meta
                    fields["sni"] = tls_meta.sni or ""
                    fields["handshake_type"] = tls_meta.handshake_type or ""
                    fields["client_version"] = tls_meta.client_version_name or ""
                    fields["is_encrypted"] = tls_meta.is_encrypted_application_data

            elif detected_proto == "QUIC/HTTP3":
                result.metadata["quic"] = {"info": "QUIC / HTTP/3 UDP Datagram"}

            elif detected_proto == "SSDP":
                result.metadata["ssdp"] = {"info": "SSDP UPnP Discovery"}

        except Exception as insp_err:
            result.inspection_errors.append(f"Inspection error in {detected_proto}: {insp_err}")
            logger.error(f"Error inspecting {detected_proto} payload: {insp_err}")

        # 3. Signature & Pattern Matching for Non-Stream or Legacy Path
        try:
            matches = self.matcher.match(
                protocol=detected_proto,
                fields=fields,
                raw_payload=payload,
            )
            result.matched_signatures = matches
            if matches:
                self.signature_matches_count += len(matches)
        except Exception as match_err:
            result.inspection_errors.append(f"Signature match error: {match_err}")
            logger.error(f"Signature matcher error: {match_err}")

        return result

