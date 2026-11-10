"""Focused verification tests for Phase 9.2 Security Audit Remediations."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock
import pytest
from fastapi import WebSocket, HTTPException

from backend.api.dependencies import verify_admin_key
from backend.api.routes.websocket import _authenticate_ws, websocket_monitor_endpoint
from backend.api.main import create_app


def test_cors_configuration_rejects_arbitrary_origins():
    """Verify CORS middleware disallows arbitrary origins while permitting localhost development."""
    app = create_app()

    cors_mw = None
    for mw in app.user_middleware:
        if "CORSMiddleware" in str(mw.cls):
            cors_mw = mw
            break

    assert cors_mw is not None
    allowed_origins = cors_mw.kwargs.get("allow_origins", [])
    allow_credentials = cors_mw.kwargs.get("allow_credentials", False)

    # Must contain development localhost
    assert "http://localhost:5173" in allowed_origins
    assert "http://127.0.0.1:5173" in allowed_origins

    # Must NOT permit universal wildcard when credentials are enabled
    if allow_credentials:
        assert "*" not in allowed_origins


def test_admin_api_key_constant_time_comparison():
    """Verify verify_admin_key succeeds with matching key and rejects mismatched keys."""
    os.environ["ADMIN_API_KEY"] = "dpi-admin-secret-key"

    # Valid X-API-Key
    assert verify_admin_key(x_api_key="dpi-admin-secret-key", authorization=None) is True

    # Valid Bearer authorization header
    assert verify_admin_key(x_api_key=None, authorization="Bearer dpi-admin-secret-key") is True

    # Invalid key
    with pytest.raises(HTTPException) as exc_info:
        verify_admin_key(x_api_key="attacker-wrong-key", authorization=None)
    assert exc_info.value.status_code == 401

    # Missing key
    with pytest.raises(HTTPException) as exc_info2:
        verify_admin_key(x_api_key=None, authorization=None)
    assert exc_info2.value.status_code == 401


def test_websocket_subprotocol_authentication_flow():
    """Verify WebSocket subprotocol negotiation accepts valid credentials and rejects invalid credentials."""
    async def _run():
        os.environ["ADMIN_API_KEY"] = "dpi-admin-secret-key"

        # 1. Valid subprotocol: 'dpi-auth, dpi-admin-secret-key'
        mock_ws_valid = AsyncMock(spec=WebSocket)
        mock_ws_valid.headers = {"sec-websocket-protocol": "dpi-auth, dpi-admin-secret-key"}
        mock_ws_valid.client = ("127.0.0.1", 54321)

        await websocket_monitor_endpoint(websocket=mock_ws_valid, token=None)
        mock_ws_valid.accept.assert_called_once_with(subprotocol="dpi-auth")

        # 2. Invalid subprotocol: 'dpi-auth, wrong-token'
        mock_ws_invalid = AsyncMock(spec=WebSocket)
        mock_ws_invalid.headers = {"sec-websocket-protocol": "dpi-auth, invalid-token-xyz"}
        mock_ws_invalid.client = ("127.0.0.1", 54322)

        await websocket_monitor_endpoint(websocket=mock_ws_invalid, token=None)
        mock_ws_invalid.close.assert_called_once_with(code=1008, reason="Unauthorized")

    asyncio.run(_run())
