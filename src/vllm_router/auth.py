# Copyright 2024-2025 The vLLM Production Stack Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

import os
import secrets

from fastapi import HTTPException, Request, status


async def  verify_api_key(request: Request) -> None:
    """
    Verify the API key from the Authorization Bearer header.

    Authentication is disabled when VLLM_API_KEY is not configured.
    """

    expected_api_key = os.getenv("VLLM_API_KEY")

    # No API key configured -> authentication disabled
    if not expected_api_key:
        return

    authorization = request.headers.get("Authorization")

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, _, api_key = authorization.partition(" ")

    if scheme.lower() != "bearer" or not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not secrets.compare_digest(api_key, expected_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )