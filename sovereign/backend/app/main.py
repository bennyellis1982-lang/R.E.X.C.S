from datetime import datetime, timedelta, timezone
from secrets import randbelow

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import auth, crud, models, schemas
from .database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sovereign API")
security = HTTPBearer()
PAIRING_CODE_TTL_MINUTES = 10


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    subject = auth.decode_access_token(creds.credentials)
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = crud.get_user_by_email(db, subject)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def healthcheck():
    return {"status": "ok"}


@app.post("/register", response_model=schemas.UserRead, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = crud.get_user_by_email(db, user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db, user)


@app.post("/login", response_model=schemas.Token)
def login(payload: schemas.UserLogin, db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": auth.create_access_token(subject=user.email)}


@app.get("/me", response_model=schemas.UserRead)
def me(user: models.User = Depends(get_current_user)):
    return user


@app.post("/pairing/ipad", response_model=schemas.PairingCode)
def create_ipad_pairing_code(user: models.User = Depends(get_current_user)):
    code = f"{randbelow(1_000_000):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=PAIRING_CODE_TTL_MINUTES)
    return {"device": "iPad", "code": code, "expires_at": expires_at}
