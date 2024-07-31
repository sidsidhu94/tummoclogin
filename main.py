from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database import engine, SessionLocal
from security import JWTAuth
from starlette.middleware.authentication import AuthenticationMiddleware

# from users.route import router as auth_router
import models
from routes import router 
from user_route import user_router

models.Base.metadata.create_all(bind = engine)

app = FastAPI()

app.include_router(router, prefix="/users")
app.include_router(user_router,prefix="/users")

app.add_middleware(AuthenticationMiddleware, backend=JWTAuth())

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get('/')
def health_check():
    return JSONResponse(content={"status": "Running!"})