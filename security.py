import os
from datetime import timedelta,datetime
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError  
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from starlette.authentication import AuthCredentials, UnauthenticatedUser

from models import UserModel
from database import engine, SessionLocal


JWT_SECRET: str = os.getenv('JWT_SECRET', '709d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7')
JWT_ALGORITHM: str = os.getenv('JWT_ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv('JWT_TOKEN_EXPIRE_MINUTES', '60'))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Token creation and payload extraction
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    return create_access_token(data=data, expires_delta=None)  

def get_token_payload(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserModel:
    payload = get_token_payload(token)
    if not payload or not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = payload.get('id')
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user")

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return user


class JWTAuth:
    
    async def authenticate(self, conn):
        guest = AuthCredentials(['unauthenticated']), UnauthenticatedUser()
        
        if 'authorization' not in conn.headers:
            return guest
        
        auth_header = conn.headers.get('authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return guest
        
        token = auth_header.split(' ')[1]  # Extract the token from the header
        try:
            # Use the FastAPI dependency to get the current user
            user = await get_current_user(token=token)
        except HTTPException:
            return guest
        
        return AuthCredentials(['authenticated']), user
    
