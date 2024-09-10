from fastapi import APIRouter, Request, HTTPException, status, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google_oauth.schema import UserSchema, AuthenticatedUserToken, RefreshTokenRequest
from google_oauth.database import get_db, Session
from google_oauth.models import User
from google_oauth.config import get_settings
from authlib.integrations.starlette_client import OAuth
from google_oauth.config import Settings
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.base_client import OAuthError
from authlib.oauth2.rfc6749 import OAuth2Token
from datetime import datetime, timedelta, timezone
import jwt

auth_router: APIRouter = APIRouter(prefix="/auth", tags=["auth"])

settings: Settings = get_settings()

# Google OAuth2 settings
GOOGLE_CLIENT_ID = settings.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = settings.GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI =  settings.google_redirect_uri

# JWT settings
JWT_SECRET_KEY = settings.JWT_SECRET_KEY
JWT_ALGORITHM = settings.JWT_ALGORITHM
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
JWT_REFRESH_TOKEN_EXPIRE_MINUTES = settings.JWT_REFRESH_TOKEN_EXPIRE_MINUTES

oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    },
    authorize_state=settings.SESSION_SECRET_KEY
)

################# JWT Workflow ###########################
async def create_token(user_id, email, time_delta_in_seconds: int):
    payload = {
        'exp': datetime.now(timezone.utc) + timedelta(seconds=time_delta_in_seconds),
        'iat': datetime.now(timezone.utc),
        'sub': email,
        'id': user_id
    }
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

async def decode_jwt_token(token: str):
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=JWT_ALGORITHM)


async def verify_jwt_token(token: str, db: Session):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bearer token is missing"
        )
    
    try:
        payload = await decode_jwt_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        expiry = payload.get("exp")
        if expiry is None or datetime.fromtimestamp(expiry, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Token has expired")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    print(f"JWT decoded for username: {username}")
    user = await get_user_by_email(username, db)

    if user is None:
        raise HTTPException(status_code=404, detail=f"JWT User {username} not found")

    print(f"User: {username} authenticated")
    return user


################# User Workflow #################
async def get_user_by_email(email: str, db: Session):
    user = db.query(User) \
        .filter(User.email == email) \
        .first()

    return user


async def create_user_from_google_info(user_info: dict, db: Session):
    user = User(
        email=user_info['email'],
        fullname=user_info['name'],
        google_sub=user_info['sub']
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user

################## Auth API ##############################

@auth_router.get("/login")
async def login(request: Request):
    redirect_uri = GOOGLE_REDIRECT_URI
    print(f"Request: {request}")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@auth_router.get("/callback/google")
async def google_auth_callback(request: Request, db: Session = Depends(get_db)):
    try:
        user_response: OAuth2Token = await oauth.google.authorize_access_token(request)
        print(f"==================Google User Response: {user_response}")
        user_info = user_response['userinfo']

        # if it is a new user, create a new user in the database
        user = await get_user_by_email(user_info['email'], db)
        if not user:
            user = await create_user_from_google_info(user_info, db)
        
        # generate the access and refresh tokens
        access_token = await create_token(user_info['sub'], user_info['email'], JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        refresh_token = await create_token(user_info['sub'], user_info['email'], JWT_REFRESH_TOKEN_EXPIRE_MINUTES * 60)

        return AuthenticatedUserToken(
            access_token=access_token,
            refresh_token=refresh_token,
            user_info=UserSchema(
                id=user.id,
                email=user.email,
                fullname=user.fullname,
                google_sub=user.google_sub
        )
    )

    except Exception as e:
        print(f"Google Oauth Exception: {e}")

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization failed"
        )


@auth_router.get("/me")
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    token = credentials.credentials

    return await verify_jwt_token(token, db)


@auth_router.post("/refresh")
async def get_current_user(
    refresh_token_request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    token = refresh_token_request.refresh_token

    user = await verify_jwt_token(token, db)

    # user is verified, regenerate the access and refresh tokens
    access_token = await create_token(user.id, user.email, JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    refresh_token = await create_token(user.id, user.email, JWT_REFRESH_TOKEN_EXPIRE_MINUTES * 60)

    return AuthenticatedUserToken(
        access_token=access_token,
        refresh_token=refresh_token,
        user_info=UserSchema(
            id=user.id,
            email=user.email,
            fullname=user.fullname,
            google_sub=user.google_sub
        )
    )

