from linecache import cache

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta

# Constants
DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# SessionLocal
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Database Models
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    posts = relationship("Post", back_populates="owner")


class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="posts")


# Database Initialization
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)
# Create a session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get the current user from the token
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return verify_token(token, credentials_exception)


# Token handling
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return user_id
    except JWTError:
        raise credentials_exception


# FastAPI App Initialization
app = FastAPI()


# Pydantic Schemas
class UserCreate(BaseModel):
    email: str
    password: str


class UserInDB(UserCreate):
    id: int


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class PostCreate(BaseModel):
    text: str


class PostSchema(BaseModel):
    id: int
    text: str
    owner_id: int


# Token creation route
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordBearer = Depends()):
    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Function to create a new user in the database and return a token
def create_new_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# Function to authenticate a user and return user details
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.email == username).first()
    if user and pwd_context.verify(password, user.password):
        return user


# Function to add a post to the database and return the post details
def add_post_to_db(db: Session, post: PostCreate, current_user: User):
    db_post = Post(**post.dict(), owner_id=current_user.id)
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post


# Function to get posts from the database and return them
def get_user_posts_from_db(db: Session, current_user: User):
    return db.query(Post).filter(Post.owner_id == current_user.id).all()


# Function to delete a post from the database
def delete_post_from_db(db: Session, post_id: int, current_user: User):
    db_post = db.query(Post).filter(Post.id == post_id, Post.owner_id == current_user.id).first()
    if db_post:
        db.delete(db_post)
        db.commit()
        return True
    return False


# Signup route
@app.post("/signup", response_model=Token)
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = create_new_user(db, user)
    token = create_token(data={"sub": db_user.email})
    return {"access_token": token, "token_type": "bearer"}


# AddPost route with token authentication and request validation
@app.post("/addPost", response_model=PostSchema)
async def add_post(post: PostCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if len(post.text.encode("utf-8")) > 1024 * 1024:  # 1 MB limit
        raise HTTPException(status_code=400, detail="Payload size exceeds 1 MB")
    db_post = add_post_to_db(db, post, current_user)
    return db_post


# GetPosts route with token authentication and response caching
@app.get("/getPosts", response_model=list[PostSchema])
async def get_posts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cached_data = cache.get(current_user.id)
    if cached_data:
        return cached_data
    user_posts = get_user_posts_from_db(db, current_user)
    cache[current_user.id] = user_posts
    return user_posts


# DeletePost route with token authentication
@app.delete("/deletePost/{post_id}")
async def delete_post(post_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if delete_post_from_db(db, post_id, current_user):
        # Clear cached data
        cache.pop(current_user.id, None)
        return {"message": "Post deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Post not found")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
