from fastapi import APIRouter, status, Depends, Request, Header
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database import engine, SessionLocal
from schemas import CreateUserRequest
from services import create_user_account,get_token, get_refresh_token
from security import oauth2_scheme
from response import UserResponse;

from fastapi.security import OAuth2PasswordRequestForm

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


router = APIRouter(
    prefix="/users",
    tags=["Users"],
    responses={404: {"description": "Not found"}},
)



@router.post('', status_code=status.HTTP_201_CREATED)
async def create_user(data: CreateUserRequest, db: Session = Depends(get_db)):
    await create_user_account(data=data, db=db)
    payload = {"message": "User account has been succesfully created."}
    return JSONResponse(content=payload)



@router.post("/token", status_code=status.HTTP_200_OK)
async def authenticate_user(data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return  get_token(data=data, db=db)

@router.post("/refresh", status_code=status.HTTP_200_OK)
async def refresh_access_token(refresh_token: str = Header(), db: Session = Depends(get_db)):
    return  get_refresh_token(token=refresh_token, db=db)