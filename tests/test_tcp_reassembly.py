"""Unit tests for TCP stream reassembly."""

from collections import deque
import time
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from parser.packet_dispatcher import PacketDispatcher
from reassembly.tcp_reassembler import TCPReassembler, DirectionalTCPStream
from models.packet_models import IPv4Header, ParsedPacket, TCPFlags, TCPHeader
from models.flow_model import FlowKey


@pytest.fixture
def dispatcher():
    return PacketDispatcher()


@pytest.fixture
def reassembler():
    return TCPReassembler()


def test_in_order_tcp_reassembly(dispatcher, reassembler):
    """Tests normal sequential multi-segment TCP stream reassembly."""
    # Segment 1: "Hello "
    p1 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=5000, dport=80, flags="A", seq=1000) / b"Hello ")
    pkt1 = dispatcher.dispatch(p1, timestamp=10.0)
    chunk1, full1 = reassembler.process_packet(pkt1)
    assert chunk1 == b"Hello "
    assert full1 == b"Hello "

    # Segment 2: "World!"
    p2 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=5000, dport=80, flags="A", seq=1006) / b"World!")
    pkt2 = dispatcher.dispatch(p2, timestamp=10.1)
    chunk2, full2 = reassembler.process_packet(pkt2)
    assert chunk2 == b"World!"
    assert full2 == b"Hello World!"


def test_out_of_order_tcp_segments(dispatcher, reassembler):
    """Tests that out-of-order segments are buffered until missing segment arrives."""
    # First: Establish baseline with SYN
    syn_pkt = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="S", seq=100))
    reassembler.process_packet(dispatcher.dispatch(syn_pkt, timestamp=1.0))

    # Send Segment 2 first (seq 111, length 10: "PART_TWO__"): expected_seq is 101, so this is OUT-OF-ORDER
    p2 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="A", seq=111) / b"PART_TWO__")
    chunk2, full2 = reassembler.process_packet(dispatcher.dispatch(p2, timestamp=1.1))
    # Should not reassemble yet because segment 1 (seq 101..110) is missing!
    assert chunk2 == b""
    assert full2 == b""

    # Now send Segment 1 (seq 101, length 10: "PART_ONE__")
    p1 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="A", seq=101) / b"PART_ONE__")
    chunk1, full1 = reassembler.process_packet(dispatcher.dispatch(p1, timestamp=1.2))

    # Both segment 1 and buffered segment 2 should now be drained!
    assert chunk1 == b"PART_ONE__PART_TWO__"
    assert full1 == b"PART_ONE__PART_TWO__"


def test_duplicate_and_retransmission():
    """Tests duplicate detection and overlapping retransmissions."""
    stream = DirectionalTCPStream()
    flags = TCPFlags(ack=True)

    # 1. Base segment: seq 1000, "ABCDE" (len 5)
    c1 = stream.push_segment(seq=1000, payload=b"ABCDE", flags=flags, timestamp=1.0)
    assert c1 == b"ABCDE"
    assert stream.expected_seq == 1005

    # 2. Exact duplicate retransmission: seq 1000, "ABCDE"
    c2 = stream.push_segment(seq=1000, payload=b"ABCDE", flags=flags, timestamp=1.1)
    assert c2 == b""  # Ignored
    assert stream.duplicate_segments == 1
    assert stream.retransmitted_segments == 1

    # 3. Partial overlap retransmission: seq 1003, "DEFG" (len 4, "DE" overlaps, "FG" is new)
    c3 = stream.push_segment(seq=1003, payload=b"DEFG", flags=flags, timestamp=1.2)
    assert c3 == b"FG"  # Only new bytes after 1005 ("FG") attached
    assert stream.get_stream_bytes() == b"ABCDEFG"


def test_missing_segment_gap(dispatcher, reassembler):
    """Tests that a missing gap is retained and does not corrupt the stream."""
    # Send seq 1000 ("AAA")
    p1 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=8080, dport=80, flags="A", seq=1000) / b"AAA")
    reassembler.process_packet(dispatcher.dispatch(p1))

    # Send seq 2000 ("BBB") -> large gap
    p2 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=8080, dport=80, flags="A", seq=2000) / b"BBB")
    chunk, full = reassembler.process_packet(dispatcher.dispatch(p2))

    assert chunk == b""
    assert full == b"AAA"


def test_bidirectional_tcp_reassembly(dispatcher, reassembler):
    """Tests independent reassembly for client->server and server->client streams."""
    # Client sends request
    p_req = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5555, dport=80, flags="PA", seq=100) / b"GET / HTTP/1.1\r\n")
    c_req, _ = reassembler.process_packet(dispatcher.dispatch(p_req))
    assert c_req == b"GET / HTTP/1.1\r\n"

    # Server sends response
    p_resp = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5555, flags="PA", seq=500) / b"HTTP/1.1 200 OK\r\n")
    c_resp, _ = reassembler.process_packet(dispatcher.dispatch(p_resp))
    assert c_resp == b"HTTP/1.1 200 OK\r\n"


# =====================================================================
# Phase 3 Enhancements: Advanced HTTP Message Framing & Stream Tests
# =====================================================================

from dpi.dpi_engine import DPIEngine
from dpi.http_inspector import HTTPMessageStreamParser, HTTPMetadata, decode_url_bounded
from reassembly.tcp_reassembler import TrafficDirection, PendingRequest


def test_http_request_split_across_segments(dispatcher, reassembler):
    """Test 1: HTTP request line and headers split across two TCP segments."""
    engine = DPIEngine()
    
    # Segment 1: "GET /admin HTTP/1.1\r\nHo"
    p1 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=4444, dport=80, flags="A", seq=100) / b"GET /admin HTTP/1.1\r\nHo")
    pkt1 = dispatcher.dispatch(p1)
    reassembler.process_packet(pkt1)
    dir_stream1, direction1, pending1 = reassembler.get_directional_context(pkt1)
    
    res1 = engine.inspect(pkt1, directional_stream=dir_stream1, direction=direction1, pending_requests=pending1)
    # Header incomplete; should not frame full message yet
    assert "http_messages" not in res1.metadata or len(res1.metadata["http_messages"]) == 0

    # Segment 2: "st: example.com\r\n\r\n"
    p2 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=4444, dport=80, flags="A", seq=123) / b"st: example.com\r\n\r\n")
    pkt2 = dispatcher.dispatch(p2)
    reassembler.process_packet(pkt2)
    dir_stream2, direction2, pending2 = reassembler.get_directional_context(pkt2)

    res2 = engine.inspect(pkt2, directional_stream=dir_stream2, direction=direction2, pending_requests=pending2)
    assert "http" in res2.metadata
    meta = res2.metadata["http"]
    assert meta.method == "GET"
    assert meta.uri == "/admin"
    assert meta.headers.get("host") == "example.com"


def test_http_headers_and_body_split_across_segments(dispatcher, reassembler):
    """Test 2: HTTP headers in segment 1 and Content-Length body in segment 2."""
    engine = DPIEngine()

    # Segment 1: POST headers with Content-Length: 11
    hdr = b"POST /api/login HTTP/1.1\r\nHost: test.local\r\nContent-Length: 11\r\n\r\n"
    p1 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.2.2.1", dst="10.2.2.2") / TCP(sport=5555, dport=80, flags="A", seq=500) / hdr)
    pkt1 = dispatcher.dispatch(p1)
    reassembler.process_packet(pkt1)
    dir_stream, direction, pending = reassembler.get_directional_context(pkt1)
    res1 = engine.inspect(pkt1, directional_stream=dir_stream, direction=direction, pending_requests=pending)
    # Body has not arrived yet; not complete
    assert "http_messages" not in res1.metadata or len(res1.metadata["http_messages"]) == 0

    # Segment 2: Body "user=admin&"
    body = b"user=admin&"
    p2 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.2.2.1", dst="10.2.2.2") / TCP(sport=5555, dport=80, flags="A", seq=500 + len(hdr)) / body)
    pkt2 = dispatcher.dispatch(p2)
    reassembler.process_packet(pkt2)
    dir_stream2, direction2, pending2 = reassembler.get_directional_context(pkt2)
    res2 = engine.inspect(pkt2, directional_stream=dir_stream2, direction=direction2, pending_requests=pending2)

    assert "http" in res2.metadata
    meta = res2.metadata["http"]
    assert meta.method == "POST"
    assert meta.content_length == 11
    assert meta.raw_body == b"user=admin&"
    assert meta.is_complete is True


def test_out_of_order_http_segment_arrival(dispatcher, reassembler):
    """Test 3: Out-of-order HTTP segments reassembled into correct message."""
    engine = DPIEngine()

    # Send SYN first
    syn = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.3.3.1", dst="10.3.3.2") / TCP(sport=6666, dport=80, flags="S", seq=1000))
    reassembler.process_packet(dispatcher.dispatch(syn))

    # Send Segment 2 first (seq 1017..1035): "Host: srv.com\r\n\r\n"
    p2 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.3.3.1", dst="10.3.3.2") / TCP(sport=6666, dport=80, flags="A", seq=1017) / b"Host: srv.com\r\n\r\n")
    pkt2 = dispatcher.dispatch(p2)
    reassembler.process_packet(pkt2)
    dir_s2, dir2, pend2 = reassembler.get_directional_context(pkt2)
    res2 = engine.inspect(pkt2, directional_stream=dir_s2, direction=dir2, pending_requests=pend2)
    assert "http_messages" not in res2.metadata or len(res2.metadata["http_messages"]) == 0

    # Send Segment 1 (seq 1001..1016): "GET / HTTP/1.1\r\n"
    p1 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.3.3.1", dst="10.3.3.2") / TCP(sport=6666, dport=80, flags="A", seq=1001) / b"GET / HTTP/1.1\r\n")
    pkt1 = dispatcher.dispatch(p1)
    reassembler.process_packet(pkt1)
    dir_s1, dir1, pend1 = reassembler.get_directional_context(pkt1)
    res1 = engine.inspect(pkt1, directional_stream=dir_s1, direction=dir1, pending_requests=pend1)

    assert "http" in res1.metadata
    meta = res1.metadata["http"]
    assert meta.method == "GET"
    assert meta.headers.get("host") == "srv.com"


def test_multiple_pipelined_http_requests_in_single_stream(dispatcher, reassembler):
    """Test 5: Multiple sequential HTTP requests framed in persistent TCP stream."""
    engine = DPIEngine()

    raw_stream = (
        b"GET /first HTTP/1.1\r\nHost: site.com\r\n\r\n"
        b"GET /second HTTP/1.1\r\nHost: site.com\r\n\r\n"
    )
    p = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.4.4.1", dst="10.4.4.2") / TCP(sport=7777, dport=80, flags="PA", seq=1) / raw_stream)
    pkt = dispatcher.dispatch(p)
    reassembler.process_packet(pkt)
    dir_s, direction, pending = reassembler.get_directional_context(pkt)
    res = engine.inspect(pkt, directional_stream=dir_s, direction=direction, pending_requests=pending)

    assert "http_messages" in res.metadata
    msgs = res.metadata["http_messages"]
    assert len(msgs) == 2
    assert msgs[0].uri == "/first"
    assert msgs[1].uri == "/second"


def test_chunked_http_request_body_decoding(dispatcher, reassembler):
    """Test 6: HTTP chunked transfer encoding (Transfer-Encoding: chunked)."""
    engine = DPIEngine()

    chunked_req = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: site.com\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"4\r\nWiki\r\n"
        b"6\r\npedia \r\n"
        b"0\r\n\r\n"
    )
    p = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.5.5.1", dst="10.5.5.2") / TCP(sport=8888, dport=80, flags="PA", seq=10) / chunked_req)
    pkt = dispatcher.dispatch(p)
    reassembler.process_packet(pkt)
    dir_s, direction, pending = reassembler.get_directional_context(pkt)
    res = engine.inspect(pkt, directional_stream=dir_s, direction=direction, pending_requests=pending)

    assert "http" in res.metadata
    meta = res.metadata["http"]
    assert meta.is_chunked is True
    assert meta.raw_body == b"Wikipedia "


def test_url_decoding_and_query_parameter_extraction():
    """Test 7: URL decoding and multi-value query parameter extraction with bounded recursion."""
    # Test double percent encoding: %252e%252e%252f -> %2e%2e%2f -> ../
    decoded = decode_url_bounded("%252e%252e%252fwindows%252fwin.ini", max_iterations=3)
    assert decoded == "../windows/win.ini"

    stream = b"GET /search?q=test%20query&id=1&id=2 HTTP/1.1\r\nHost: local\r\n\r\n"
    msgs, consumed = HTTPMessageStreamParser.parse_messages(stream, direction=TrafficDirection.CLIENT_TO_SERVER)
    assert len(msgs) == 1
    m = msgs[0]
    assert m.raw_uri == "/search?q=test%20query&id=1&id=2"
    assert m.normalized_uri == "/search?q=test query&id=1&id=2"
    assert m.query_params["id"] == ["1", "2"]
    assert m.normalized_query_params["q"] == ["test query"]


def test_attack_signature_split_across_tcp_segments(dispatcher, reassembler):
    """Test 8: Attack signature split across segments is detected on reassembled stream."""
    engine = DPIEngine()

    # Rule 1002 matches exact '/.env'
    # Segment 1: "GET /." (seq 1, len 6 -> next seq 7)
    p1 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.6.6.1", dst="10.6.6.2") / TCP(sport=9999, dport=80, flags="A", seq=1) / b"GET /.")
    pkt1 = dispatcher.dispatch(p1)
    reassembler.process_packet(pkt1)
    dir1, d1, pend1 = reassembler.get_directional_context(pkt1)
    res1 = engine.inspect(pkt1, directional_stream=dir1, direction=d1, pending_requests=pend1)
    assert len(res1.matched_signatures) == 0

    # Segment 2: "env HTTP/1.1\r\nHost: x\r\n\r\n" (seq 7, contiguous!)
    p2 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.6.6.1", dst="10.6.6.2") / TCP(sport=9999, dport=80, flags="A", seq=7) / b"env HTTP/1.1\r\nHost: x\r\n\r\n")
    pkt2 = dispatcher.dispatch(p2)
    reassembler.process_packet(pkt2)
    dir2, d2, pend2 = reassembler.get_directional_context(pkt2)
    res2 = engine.inspect(pkt2, directional_stream=dir2, direction=d2, pending_requests=pend2)

    # Reassembled stream URI becomes '/.env' and triggers rule 1002!
    assert len(res2.matched_signatures) > 0
    rule_ids = [m["id"] if isinstance(m, dict) else getattr(m, "rule_id", None) for m in res2.matched_signatures]
    assert 1002 in rule_ids


def test_head_and_informational_response_correlation(dispatcher, reassembler):
    """Test: HEAD response framing (zero body) and 1xx informational correlation."""
    engine = DPIEngine()

    # Client issues HEAD request
    p_head = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.7.7.1", dst="10.7.7.2") / TCP(sport=3333, dport=80, flags="PA", seq=100) / b"HEAD /file.iso HTTP/1.1\r\nHost: x\r\n\r\n")
    pkt_h = dispatcher.dispatch(p_head)
    reassembler.process_packet(pkt_h)
    dir_h, d_h, pend_h = reassembler.get_directional_context(pkt_h)
    engine.inspect(pkt_h, directional_stream=dir_h, direction=d_h, pending_requests=pend_h)
    assert len(pend_h) == 1
    assert pend_h[0].method == "HEAD"

    # Server sends 100 Continue followed by 200 OK with Content-Length: 999999
    # HEAD response must have ZERO body despite Content-Length!
    resp_data = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n"
    )
    p_resp = bytes(Ether(src="00:06:07:08:09:0a", dst="00:01:02:03:04:05") / IP(src="10.7.7.2", dst="10.7.7.1") / TCP(sport=80, dport=3333, flags="PA", seq=200) / resp_data)
    pkt_r = dispatcher.dispatch(p_resp)
    reassembler.process_packet(pkt_r)
    dir_r, d_r, pend_r = reassembler.get_directional_context(pkt_r)
    res_r = engine.inspect(pkt_r, directional_stream=dir_r, direction=d_r, pending_requests=pend_r)

    assert "http_messages" in res_r.metadata
    msgs = res_r.metadata["http_messages"]
    assert len(msgs) == 2
    assert msgs[0].status_code == 100
    assert msgs[1].status_code == 200
    assert msgs[1].framing_method == "HEAD_RESPONSE"
    assert msgs[1].raw_body == b""


def test_connection_rst_vs_fin_termination(dispatcher, reassembler):
    """Test: Distinguishing FIN vs RST on close-delimited responses."""
    # Scenario A: Server closes with FIN -> close-delimited response is valid
    resp_body = b"HTTP/1.1 200 OK\r\n\r\nEnd of data."
    p_fin = bytes(Ether(src="00:06:07:08:09:0a", dst="00:01:02:03:04:05") / IP(src="10.8.8.2", dst="10.8.8.1") / TCP(sport=80, dport=4444, flags="FA", seq=100) / resp_body)
    pkt_f = dispatcher.dispatch(p_fin)
    reassembler.process_packet(pkt_f)
    dir_f, _, _ = reassembler.get_directional_context(pkt_f)
    assert dir_f.is_terminated is True
    assert dir_f.termination_type == "FIN"
    msgs, _ = HTTPMessageStreamParser.parse_messages(dir_f.get_unconsumed_bytes(), direction=TrafficDirection.SERVER_TO_CLIENT, is_connection_closed=True, termination_type="FIN")
    assert len(msgs) == 1
    assert msgs[0].framing_method == "CLOSE_DELIMITED"
    assert msgs[0].is_complete is True

    # Scenario B: Server connection aborted with RST -> not treated as complete close-delimited
    p_rst = bytes(Ether(src="00:06:07:08:09:0a", dst="00:01:02:03:04:05") / IP(src="10.9.9.2", dst="10.9.9.1") / TCP(sport=80, dport=5555, flags="R", seq=200))
    pkt_r = dispatcher.dispatch(p_rst)
    reassembler.process_packet(pkt_r)
    dir_r, _, _ = reassembler.get_directional_context(pkt_r)
    assert dir_r.is_terminated is True
    assert dir_r.termination_type == "RST"


def test_duplicate_alert_prevention_on_stream_updates(dispatcher, reassembler):
    """Test 12: Ensure already alerted HTTP message does not re-alert on subsequent packet arrival."""
    engine = DPIEngine()

    # Packet 1 contains full request: "/.env"
    p1 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.10.10.1", dst="10.10.10.2") / TCP(sport=1234, dport=80, flags="PA", seq=1) / b"GET /.env HTTP/1.1\r\nHost: a\r\n\r\n")
    pkt1 = dispatcher.dispatch(p1)
    reassembler.process_packet(pkt1)
    dir1, d1, pend1 = reassembler.get_directional_context(pkt1)
    res1 = engine.inspect(pkt1, directional_stream=dir1, direction=d1, pending_requests=pend1)
    assert len(res1.matched_signatures) == 1

    # Packet 2 in same stream: ACK packet without new HTTP message
    p2 = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.10.10.1", dst="10.10.10.2") / TCP(sport=1234, dport=80, flags="A", seq=34))
    pkt2 = dispatcher.dispatch(p2)
    reassembler.process_packet(pkt2)
    dir2, d2, pend2 = reassembler.get_directional_context(pkt2)
    res2 = engine.inspect(pkt2, directional_stream=dir2, direction=d2, pending_requests=pend2)
    # The message has already been inspected; no duplicate alert produced!
    assert len(res2.matched_signatures) == 0


# =====================================================================
# Phase 3.2: HTTP Parser Hardening & Advanced Framing Tests
# =====================================================================

def test_conflicting_multiple_content_length_headers():
    """Asserts that conflicting multiple Content-Length headers are flagged as ambiguous."""
    stream = b"GET /data HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n12345"
    msgs, consumed = HTTPMessageStreamParser.parse_messages(stream, direction=TrafficDirection.CLIENT_TO_SERVER)
    assert len(msgs) == 1
    m = msgs[0]
    assert m.framing_method == "AMBIGUOUS_CONTENT_LENGTH"
    assert m.content_length == 5
    assert m.raw_body == b"12345"
    assert m.is_complete is True


def test_identical_duplicate_content_length_headers():
    """Asserts that identical duplicate Content-Length headers are accepted cleanly."""
    stream = b"POST /submit HTTP/1.1\r\nHost: test.com\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nDATA"
    msgs, consumed = HTTPMessageStreamParser.parse_messages(stream, direction=TrafficDirection.CLIENT_TO_SERVER)
    assert len(msgs) == 1
    m = msgs[0]
    assert m.framing_method == "CONTENT_LENGTH"
    assert m.content_length == 4
    assert m.raw_body == b"DATA"
    assert m.is_complete is True


def test_transfer_encoding_combined_with_content_length():
    """Asserts that Transfer-Encoding overrides Content-Length and flags ambiguity."""
    chunked_req = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: test.com\r\n"
        b"Content-Length: 100\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"5\r\nHELLO\r\n"
        b"0\r\n\r\n"
    )
    msgs, consumed = HTTPMessageStreamParser.parse_messages(chunked_req, direction=TrafficDirection.CLIENT_TO_SERVER)
    assert len(msgs) == 1
    m = msgs[0]
    assert m.is_chunked is True
    assert "AMBIGUOUS" in m.framing_method
    assert m.raw_body == b"HELLO"
    assert m.is_complete is True


def test_http_103_early_hints_followed_by_final_response():
    """Asserts that 103 Early Hints does not pop pending request and frames with zero body."""
    pending_q = deque([PendingRequest(method="GET", uri="/app.js", timestamp=time.time(), seq_index=1)])
    resp_stream = (
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nconsole.log()"
    )
    msgs, consumed = HTTPMessageStreamParser.parse_messages(
        resp_stream,
        direction=TrafficDirection.SERVER_TO_CLIENT,
        pending_requests=pending_q,
    )
    assert len(msgs) == 2
    # 103 Early Hints check
    assert msgs[0].status_code == 103
    assert msgs[0].raw_body == b""
    assert msgs[0].is_complete is True
    # 200 OK final response check
    assert msgs[1].status_code == 200
    assert msgs[1].raw_body == b"console.log()"
    assert msgs[1].is_complete is True
    # Pending request was popped only upon final response
    assert len(pending_q) == 0


def test_http_204_and_304_zero_body_responses():
    """Asserts that 204 No Content and 304 Not Modified have zero body even with Content-Length."""
    pending_q = deque([
        PendingRequest(method="DELETE", uri="/item/1", timestamp=time.time(), seq_index=1),
        PendingRequest(method="GET", uri="/cached.html", timestamp=time.time(), seq_index=2),
    ])
    resp_stream = (
        b"HTTP/1.1 204 No Content\r\nContent-Length: 50\r\n\r\n"
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n"
    )
    msgs, consumed = HTTPMessageStreamParser.parse_messages(
        resp_stream,
        direction=TrafficDirection.SERVER_TO_CLIENT,
        pending_requests=pending_q,
    )
    assert len(msgs) == 2
    assert msgs[0].status_code == 204
    assert msgs[0].raw_body == b""
    assert msgs[0].framing_method == "STATUS_204_NO_BODY"

    assert msgs[1].status_code == 304
    assert msgs[1].raw_body == b""
    assert msgs[1].framing_method == "STATUS_304_NO_BODY"
    assert len(pending_q) == 0


def test_get_request_with_content_length_body():
    """Asserts that GET requests with Content-Length body wait for and capture body payload."""
    req_stream = b"GET /query HTTP/1.1\r\nHost: test.com\r\nContent-Length: 8\r\n\r\nFILTER=1"
    msgs, consumed = HTTPMessageStreamParser.parse_messages(req_stream, direction=TrafficDirection.CLIENT_TO_SERVER)
    assert len(msgs) == 1
    m = msgs[0]
    assert m.method == "GET"
    assert m.content_length == 8
    assert m.raw_body == b"FILTER=1"
    assert m.is_complete is True


def test_chunk_extensions_and_trailers():
    """Asserts that chunk extensions (;ext=val) and post-terminal trailers are stripped without body corruption."""
    chunked_data = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: test.com\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"4;extension=data\r\nTest\r\n"
        b"0\r\n"
        b"Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\n\r\n"
    )
    msgs, consumed = HTTPMessageStreamParser.parse_messages(chunked_data, direction=TrafficDirection.CLIENT_TO_SERVER)
    assert len(msgs) == 1
    m = msgs[0]
    assert m.is_chunked is True
    assert m.raw_body == b"Test"
    assert m.is_complete is True


def test_incomplete_message_30s_timeout():
    """Asserts that an incomplete HTTP message times out after 30 seconds and is safely cleared."""
    stream = DirectionalTCPStream()
    flags = TCPFlags(ack=True)
    # Push partial HTTP request (no terminating CRLF CRLF)
    stream.push_segment(seq=1, payload=b"GET /incomplete_path HTTP/1.1\r\nHost: a", flags=flags, timestamp=100.0)

    # First check at t=110s (elapsed 10s < 30s) -> should NOT time out
    assert stream.check_incomplete_timeout(now=110.0) is False
    assert len(stream.get_unconsumed_bytes()) > 0

    # Second check at t=135s (elapsed 35s > 30s) -> should time out and clean up
    assert stream.check_incomplete_timeout(now=135.0) is True
    assert stream.is_truncated is True
    assert stream.truncation_reason == "INCOMPLETE_MESSAGE_TIMEOUT_30S"
    assert stream.get_unconsumed_bytes() == b""


def test_desynchronization_false_startline_prevention():
    """Asserts that arbitrary suffix bytes are rejected and not parsed as fake HTTP messages."""
    # Arbitrary binary data containing substring "POST" in the middle of a non-HTTP sentence
    garbage = b"\x00\xffRandom data without valid HTTP start line POST some junk\r\n\r\n"
    msgs, consumed = HTTPMessageStreamParser.parse_messages(garbage, direction=TrafficDirection.CLIENT_TO_SERVER)
    # Must reject false start line and produce zero valid messages
    assert len(msgs) == 0


def test_pending_request_queue_overflow_marks_uncertain(dispatcher):
    """Asserts that pending request queue caps at 128 and marks correlation uncertain upon eviction."""
    reassembler = TCPReassembler()
    # Create valid packet via dispatcher to establish flow
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S", seq=1))
    p = dispatcher.dispatch(pkt_raw)
    reassembler.process_packet(p)
    key, _ = FlowKey.from_packet(p)

    # Push 128 requests: all fit cleanly
    for i in range(128):
        uncertain = reassembler.add_pending_request(key, PendingRequest(method="GET", uri=f"/req_{i}", timestamp=time.time(), seq_index=i))
        assert uncertain is False

    # Push 129th request: causes eviction and marks correlation uncertain
    uncertain = reassembler.add_pending_request(key, PendingRequest(method="GET", uri="/req_129", timestamp=time.time(), seq_index=129))
    assert uncertain is True
    assert len(reassembler._pending_requests[key]) == 128


