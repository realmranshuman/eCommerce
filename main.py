from fastapi import Depends, FastAPI, HTTPException, Request, File, UploadFile, Form
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ValidationError
import bcrypt
import jwt
from jwt import PyJWTError
import sqlite3


# App And Middlewares
app = FastAPI()
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Folder/Directory where static files are going to be stored
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates/Pages to be stored in this folder/directory
templates = Jinja2Templates(directory="templates")

# Connection to the database
conn = sqlite3.connect('eCommerce.db')

# USER LOGIN USING oAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token",)

# The best wy to do it is to store it into different file. Never commit it to production like this
SECRET_KEY = "b94f8e6272fcef848060d16721461f19439147462768dadfaf9e132b5e7d5dca"
ALGORITHM = "HS256"

def get_user_type(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except (PyJWTError, ValidationError):
        raise HTTPException(
            status_code=400,
            detail="Invalid JWT or expired token"
        )

def authenticate_user(email: str, password: str, conn):
    c = conn.cursor()
    c.execute("SELECT * FROM customers WHERE email =?", (email,))
    user = c.fetchone()
    user_type = 'customer'
    if user:
        hashed_password = user[3]
        # Encode the password before passing it to the bcrypt.checkpw() function
        encoded_password = bytes(password, 'utf-8')
        if bcrypt.checkpw(encoded_password, hashed_password):
            return user, user_type

    c.execute("SELECT * FROM admins WHERE email =?", (email,))
    user = c.fetchone()
    user_type = 'admin'
    if user:
        hashed_password = user[3]
        # Encode the password before passing it to the bcrypt.checkpw() function
        encoded_password = bytes(password, 'utf-8')
        if bcrypt.checkpw(encoded_password, hashed_password):
            return user, user_type
    c.execute("SELECT * FROM vendors WHERE email =?", (email,))
    user = c.fetchone()
    user_type = 'vendor'
    if user:
        hashed_password = user[3]
        # Encode the password before passing it to the bcrypt.checkpw() function
        encoded_password = bytes(password, 'utf-8')
        if bcrypt.checkpw(encoded_password, hashed_password):
            return user, user_type
    return None

def create_access_token(payload: dict, expires_delta: timedelta | None = None):
    payload_copy = payload.copy()
    if expires_delta:
        expires = datetime.utcnow() + expires_delta
    else:
        expires = datetime.utcnow() + timedelta(minutes=15)
    payload_copy.update({"exp": expires})
    token = jwt.encode(payload_copy, SECRET_KEY, algorithm=ALGORITHM)
    return token

@app.post("/token", status_code=201)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username
    password = form_data.password
    user, user_type = authenticate_user(email, password, conn)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(hours=24)
    access_token = create_access_token(
        payload={"sub": user[2], "name": user[1], "type": user_type}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}



# eCommerce Homepage
@app.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("homepage.html", {"request": request})

@app.get("/customer-page")
async def customer_page(payload: dict = Depends(get_user_type)):
    if payload['type'] != 'customer':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM customers WHERE email =?", (payload['sub'],))
    customer = c.fetchone()
    if not customer:
        raise HTTPException(
            status_code=404,
            detail="customer not found"
        )
    return {"customer_name": customer[1]}

@app.post("/customers/signup")
async def customer_signup(name: str, email: str, password: str):
    c = conn.cursor()
    # check if email already exists in the table
    c.execute("SELECT email FROM customers WHERE email =?", (email,))
    email_exists = c.fetchone()
    if email_exists:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )
    # generate unique salt
    salt = bcrypt.gensalt()
    # hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    # store the hashed password and salt in the customers table
    c.execute("INSERT INTO customers (name, email, hashed_password) VALUES (?,?,?)",
              (name, email, hashed_password))
    conn.commit()
    return {"message": "Customer created successfully"}
