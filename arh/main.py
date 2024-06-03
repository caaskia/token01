from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer
import redis.asyncio as redis
import secrets
from datetime import timedelta

app = FastAPI()
auth_dep = AuthJWTBearer()


class User(BaseModel):
    username: str
    password: str


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_token_location: set = {"cookies"}
    authjwt_cookie_csrf_protect: bool = False
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access", "refresh"}
    access_expires: timedelta = timedelta(minutes=15)
    refresh_expires: timedelta = timedelta(days=30)


settings = Settings()


@AuthJWT.load_config
def get_config():
    return settings


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


redis_conn = redis.from_url("redis://localhost", decode_responses=True)


@AuthJWT.token_in_denylist_loader
async def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token["jti"]
    entry = await redis_conn.get(jti)
    return entry and entry == "true"


async def set_jwt_cookies(authorize: AuthJWT, access_token: str, refresh_token: str):
    await authorize.set_access_cookies(access_token)
    await authorize.set_refresh_cookies(refresh_token)


@app.post("/login")
async def login(user: User, authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = await authorize.create_access_token(subject=user.username)
    refresh_token = await authorize.create_refresh_token(subject=user.username)

    jti = (await authorize.get_raw_jwt(access_token))["jti"]
    await redis_conn.set(f"active_jti_{user.username}", jti)

    await set_jwt_cookies(authorize, access_token, refresh_token)
    return {"msg": "Successfully login"}


@app.post("/refresh")
async def refresh(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_refresh_token_required()
    current_user = await authorize.get_jwt_subject()
    new_access_token = await authorize.create_access_token(subject=current_user)
    new_refresh_token = await authorize.create_refresh_token(subject=current_user)

    await set_jwt_cookies(authorize, new_access_token, new_refresh_token)
    return {"msg": "The tokens have been refreshed"}


@app.delete("/logout")
async def logout(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()
    await authorize.unset_jwt_cookies()
    return {"msg": "Successfully logout"}


@app.post("/logout-others")
async def logout_others(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()
    current_user = await authorize.get_jwt_subject()

    new_jti = secrets.token_urlsafe()
    await redis_conn.set(f"active_jti_{current_user}", new_jti)

    return {"msg": "All other sessions have been logged out"}


@app.delete("/access-revoke")
async def access_revoke(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()
    jti = (await authorize.get_raw_jwt())["jti"]
    await redis_conn.setex(jti, int(settings.access_expires.total_seconds()), "true")
    return {"msg": "Access token has been revoked"}


@app.delete("/refresh-revoke")
async def refresh_revoke(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_refresh_token_required()
    jti = (await authorize.get_raw_jwt())["jti"]
    await redis_conn.setex(jti, int(settings.refresh_expires.total_seconds()), "true")
    return {"msg": "Refresh token has been revoked"}


@app.get("/protected")
async def protected(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()
    current_user = await authorize.get_jwt_subject()

    jti = (await authorize.get_raw_jwt())["jti"]
    active_jti = await redis_conn.get(f"active_jti_{current_user}")

    if jti != active_jti:
        raise HTTPException(status_code=401, detail="Session has expired due to logout from another device")

    return {"user": current_user}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
