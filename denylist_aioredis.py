from datetime import timedelta
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import redis.asyncio as redis
from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer

app = FastAPI()
auth_dep = AuthJWTBearer()

class User(BaseModel):
    username: str
    password: str

class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access", "refresh"}
    access_expires: timedelta = timedelta(minutes=15)
    refresh_expires: timedelta = timedelta(days=30)

settings = Settings()

@AuthJWT.load_config
def get_config():
    return settings

@app.exception_handler(AuthJWTException)
async def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

redis_conn = redis.from_url("redis://localhost", decode_responses=True)

@AuthJWT.token_in_denylist_loader
async def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token["jti"]
    entry = await redis_conn.get(jti)
    return entry and entry == "true"

@app.post("/login")
async def login(user: User, authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = await authorize.create_access_token(subject=user.username)
    refresh_token = await authorize.create_refresh_token(subject=user.username)

    # Debug print statements
    print(f"Access Token: {access_token}")
    print(f"Refresh Token: {refresh_token}")

    return {"access_token": access_token, "refresh_token": refresh_token}

@app.post("/refresh")
async def refresh(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_refresh_token_required()
    current_user = await authorize.get_jwt_subject()
    new_access_token = await authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}

@app.delete("/access-revoke")
async def access_revoke(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()
    jti = (await authorize.get_raw_jwt())["jti"]
    await redis_conn.setex(jti, int(settings.access_expires.total_seconds()), "true")
    return {"detail": "Access token has been revoked"}

@app.delete("/refresh-revoke")
async def refresh_revoke(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_refresh_token_required()
    jti = (await authorize.get_raw_jwt())["jti"]
    await redis_conn.setex(jti, int(settings.refresh_expires.total_seconds()), "true")
    return {"detail": "Refresh token has been revoked"}

@app.get("/protected")
async def protected(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()
    current_user = await authorize.get_jwt_subject()
    return {"user": current_user}

# New logout endpoint
@app.post("/logout")
async def logout(authorize: AuthJWT = Depends(auth_dep)):
    # Revoke access token
    await authorize.jwt_required()
    access_jti = (await authorize.get_raw_jwt())["jti"]
    await redis_conn.setex(access_jti, int(settings.access_expires.total_seconds()), "true")

    # Revoke refresh token
    await authorize.jwt_refresh_token_required()
    refresh_jti = (await authorize.get_raw_jwt())["jti"]
    await redis_conn.setex(refresh_jti, int(settings.refresh_expires.total_seconds()), "true")

    return {"detail": "Tokens have been revoked"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("denylist_aioredis:app", host="0.0.0.0", port=8000, reload=True)
