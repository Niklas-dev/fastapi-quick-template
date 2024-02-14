from fastapi import APIRouter, Depends, HTTPException
from datetime import timedelta, datetime, UTC
from typing import Annotated

from starlette import status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session, defer
from authlib.integrations.starlette_client import OAuth
import os
from jose import jwt, JWTError
from starlette.config import Config

from .validators import GoogleUser
from .models import User
from ...db.database import db_dependency

ALGORITHM = "HS256"

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID') or None
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET') or None

if GOOGLE_CLIENT_ID is None or GOOGLE_CLIENT_SECRET is None:
    raise Exception('Missing env variables')

config_data = {'GOOGLE_CLIENT_ID': GOOGLE_CLIENT_ID, 'GOOGLE_CLIENT_SECRET': GOOGLE_CLIENT_SECRET}

starlette_config = Config(environ=config_data)

oauth = OAuth(starlette_config)

oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)


def authenticate_user(username: str, password: str, db: type[Session]):
    user: User = db.query(User).filter(User.username == username).first()

    if not user:
        return False

    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {"sub": username, "id": user_id}

    expires = datetime.now(UTC) + expires_delta

    encode.update({"exp": expires})

    return jwt.encode(encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)


def create_refresh_token(username: str, user_id: int, expires_delta: timedelta):
    return create_access_token(username, user_id, expires_delta)


def decode_token(token):
    return jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=ALGORITHM)


def get_current_user(token: Annotated[str, Depends(oauth_bearer)], db: db_dependency):
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=ALGORITHM)
        username: str = payload.get("sub")
        user_id: int = payload.get("id")

        user: User = db.query(User).filter(User.username == str(username)).options(
            defer(User.hashed_password), defer(User.google_sub)).first()

        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")


def token_expired(token: Annotated[str, Depends(oauth_bearer)]):
    try:
        payload = decode_token(token)
        if not datetime.fromtimestamp(payload.get('exp'), UTC) > datetime.now(UTC):
            return True
        return False

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")


def get_user_by_google_sub(google_sub: int, db: Session):
    return db.query(User).filter(User.google_sub == str(google_sub)).first()


def create_user_from_google_info(google_user: GoogleUser, db: Session):
    google_sub = google_user.sub
    email = google_user.email

    existing_user = db.query(User).filter(User.email == email).first()

    if existing_user:

        existing_user.google_id = google_sub
        db.commit()
        return existing_user
    else:

        new_user = User(
            username=email,
            email=email,
            google_sub=google_sub,

        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user


user_dependency = Annotated[dict, Depends(get_current_user)]
