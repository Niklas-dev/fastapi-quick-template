from authlib.integrations.base_client import OAuthError
from authlib.oauth2.rfc6749 import OAuth2Token
from fastapi import APIRouter, Depends, HTTPException
from datetime import timedelta
from typing import Annotated
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm
import requests
from .models import User
from .validators import CreateUserRequest, GoogleUser, Token, RefreshTokenRequest
from .services import create_access_token, authenticate_user, bcrypt_context, create_refresh_token, \
    create_user_from_google_info, get_user_by_google_sub, token_expired, decode_token, user_dependency
from ...db.database import db_dependency
from .services import oauth
from fastapi import Request
from fastapi.responses import RedirectResponse
import os
router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = "http://localhost/auth/callback/google"
FRONTEND_URL = os.getenv("FRONTEND_URL")


@router.get("/google")
async def login_google(request: Request):
    return await oauth.google.authorize_redirect(request, GOOGLE_REDIRECT_URI)


@router.get("/callback/google")
async def auth_google(request: Request, db: db_dependency):
    try:
        user_response: OAuth2Token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

    user_info = user_response.get("userinfo")

    print(user_info)

    google_user = GoogleUser(**user_info)

    existing_user = get_user_by_google_sub(google_user.sub, db)

    if existing_user:
        print("Existing user")
        user = existing_user
    else:
        print("Creating user")
        user = create_user_from_google_info(google_user, db)

    access_token = create_access_token(user.username, user.id, timedelta(days=7))
    refresh_token = create_refresh_token(user.username, user.id, timedelta(days=14))

    return RedirectResponse(f"{FRONTEND_URL}/auth?access_token={access_token}&refresh_token={refresh_token}")


@router.post("/create-user", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    create_user_model = User(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password)
    )

    db.add(create_user_model)
    db.commit()

    return create_user_request


@router.get("/get-user", status_code=status.HTTP_201_CREATED)
async def get_user(db: db_dependency, user: user_dependency):
    return user


@router.post("/token", response_model=Token, status_code=status.HTTP_200_OK)
async def login_for_access_token(db: db_dependency, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")

    access_token = create_access_token(user.username, user.id, timedelta(days=7))
    refresh_token = create_refresh_token(user.username, user.id, timedelta(days=14))

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh", response_model=Token)
async def refresh_access_token(db: db_dependency, refresh_token_request: RefreshTokenRequest):
    token = refresh_token_request.refresh_token

    if token_expired(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token is expired.")

    user = decode_token(token)
    print(f"Refreshed token for {user.username}")

    access_token = create_access_token(user.username, user.id, timedelta(days=7))
    refresh_token = create_refresh_token(user.username, user.id, timedelta(days=14))

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
