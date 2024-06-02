from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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


@AuthJWT.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.post("/login")
async def login(user: User, authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = await authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}


@app.get("/partially-protected")
async def partially_protected(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_optional()

    # If no jwt is sent in the request, get_jwt_subject() will return None
    current_user = await authorize.get_jwt_subject() or "anonymous"
    return {"user": current_user}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("jwt_optional:app", host="0.0.0.0", port=8000, reload=True)