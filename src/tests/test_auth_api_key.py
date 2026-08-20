from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from vllm_router.auth import verify_api_key

# ---------------------------------------------------------------------------
# verify_api_key dependency
# ---------------------------------------------------------------------------


def _make_request(auth_header: str | None = None) -> MagicMock:
    request = MagicMock()
    headers = {}
    if auth_header is not None:
        headers["Authorization"] = auth_header
    request.headers = headers
    return request


@pytest.mark.anyio
async def test_verify_no_keys_configured_allows_all(monkeypatch):
    monkeypatch.delenv("VLLM_API_KEY", raising=False)
    request = _make_request()
    await verify_api_key(request)  # must not raise


@pytest.mark.anyio
async def test_verify_valid_single_key(monkeypatch):
    monkeypatch.setenv("VLLM_API_KEY", "secret")
    request = _make_request("Bearer secret")
    await verify_api_key(request)  # must not raise


@pytest.mark.anyio
async def test_verify_invalid_key_raises_401(monkeypatch):
    monkeypatch.setenv("VLLM_API_KEY", "key1,key2")
    request = _make_request("Bearer wrong-key")
    with pytest.raises(HTTPException) as exc_info:
        await verify_api_key(request)
    assert exc_info.value.status_code == 401


@pytest.mark.anyio
async def test_verify_missing_auth_header_raises_401(monkeypatch):
    monkeypatch.setenv("VLLM_API_KEY", "secret")
    request = _make_request()  # no Authorization header
    with pytest.raises(HTTPException) as exc_info:
        await verify_api_key(request)
    assert exc_info.value.status_code == 401


@pytest.mark.anyio
async def test_verify_non_bearer_scheme_raises_401(monkeypatch):
    monkeypatch.setenv("VLLM_API_KEY", "secret")
    request = _make_request("Basic secret")
    with pytest.raises(HTTPException) as exc_info:
        await verify_api_key(request)
    assert exc_info.value.status_code == 401
