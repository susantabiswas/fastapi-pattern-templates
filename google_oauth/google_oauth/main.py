from fastapi import FastAPI
import uvicorn
from google_oauth.config import get_settings
from google_oauth.auth import auth_router
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from google_oauth.database import Base, engine

settings = get_settings()

app = FastAPI()

# add the session middleware to the app to keep track of user's session
# when they have authenticated with google
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)
app.include_router(auth_router)


origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sync the DB models with the database
Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {"message": "Hello World"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.fastapi_port)
