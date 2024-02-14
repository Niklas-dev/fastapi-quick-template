from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI, status, HTTPException
from app.db.database import engine, db_dependency
from app.routers.auth.services import user_dependency
from app.routers.auth import models as auth_models
from app.routers.auth.auth import router as auth_router
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import logging
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

origins = ["*"]

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.include_router(auth_router)

auth_models.Base.metadata.create_all(bind=engine)



@app.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed.")

    return {"user": user}


@app.get("/test", status_code=status.HTTP_200_OK)
async def test(db: db_dependency):
    return "test"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app="main:app", host="0.0.0.0", port=80, reload=True)
