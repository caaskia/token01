# uv pip install pytest httpx

import pytest
import httpx
from fastapi import status

base_url = "http://localhost:8000"

@pytest.fixture
def client():
    with httpx.Client(base_url=base_url) as client:
        yield client

def test_register_user(client):
    response = client.post("/register", json={"username": "test", "password": "test"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"msg": "User registered successfully"}

def test_register_existing_user(client):
    response = client.post("/register", json={"username": "test", "password": "test"})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Username already exists"}

def test_login(client):
    response = client.post("/login", json={"username": "test", "password": "test"})
    assert response.status_code == status.HTTP_200_OK
    assert response.cookies.get("access_token_cookie")
    assert response.cookies.get("refresh_token_cookie")
    client.cookies = response.cookies

def test_protected_route(client):
    response = client.get("/protected")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"user": "test"}

def test_refresh_tokens(client):
    response = client.post("/refresh")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"msg": "The tokens have been refreshed"}
    assert response.cookies.get("access_token_cookie")
    assert response.cookies.get("refresh_token_cookie")
    client.cookies = response.cookies

def test_revoke_refresh_token(client):
    response = client.delete("/refresh-revoke")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"msg": "Refresh token has been revoked"}
    # Try to refresh token after revoking refresh token
    response = client.post("/refresh")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "Token has been revoked"}


def test_revoke_access_token(client):
    response = client.delete("/access-revoke")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"msg": "Access token has been revoked"}
    # Try to access protected route after revoking access token
    response = client.get("/protected")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "Token has been revoked"}

def test_logout_others(client):
    response = client.post("/logout-others")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"msg": "All other sessions have been logged out"}

def test_full_workflow(client):
    test_register_user(client)
    test_register_existing_user(client)
    test_login(client)
    test_protected_route(client)
    test_refresh_tokens(client)
    test_revoke_refresh_token(client)
    test_login(client)  # Re-login to get valid tokens
    test_protected_route(client)
    test_revoke_access_token(client)
    test_login(client)  # Re-login to get valid tokens
    test_protected_route(client)
    test_logout_others(client)
