from fastapi import Depends, FastAPI, HTTPException, Request, File, UploadFile, Form
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse, Response
import starlette.status as status
from typing import List, Optional
from datetime import datetime
from pydantic import ValidationError
import random
import json
import re
import bcrypt
import jwt
from jwt import PyJWTError
import sqlite3
import os


# App And Middlewares
app = FastAPI()
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Folder/Directory where static files are going to be stored
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates/Pages to be stored in this folder/directory
templates = Jinja2Templates(directory="templates")

# Connection to the database
conn = sqlite3.connect('eCommerce.db')

# USER LOGIN USING JSON Web Tokens
# The best wy to do it is to store it into different file. Never commit it to production like this
SECRET_KEY = "b94f8e6272fcef848060d16721461f19439147462768dadfaf9e132b5e7d5dca"
ALGORITHM = "HS256"

def get_user_type(token):
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
    conn.commit()
    user_type = 'customer'
    if user:
        hashed_password = user[3]
        encoded_password = bytes(password, 'utf-8')
        if bcrypt.checkpw(encoded_password, hashed_password):
            return user, user_type
    # Check if the user is an admin
    c.execute("SELECT * FROM admins WHERE email =?", (email,))
    user = c.fetchone()
    conn.commit()
    user_type = 'admin'
    if user:
        hashed_password = user[3]
        encoded_password = bytes(password, 'utf-8')
        if bcrypt.checkpw(encoded_password, hashed_password):
            return user, user_type
    # Check if the customer is a vendor type
    c.execute("SELECT * FROM vendors WHERE email =?", (email,))
    user = c.fetchone()
    conn.commit()
    user_type = 'vendor'
    if user:
        hashed_password = user[3]
        encoded_password = bytes(password, 'utf-8')
        if bcrypt.checkpw(encoded_password, hashed_password):
            return user, user_type
    return None, ""

def create_access_token(payload: dict | None = None):
    payload_copy = payload.copy()
    token = jwt.encode(payload_copy, SECRET_KEY, algorithm=ALGORITHM)
    return token

@app.post("/token", status_code=201)
async def login(request: Request, response: Response, email: str = Form(...), password: str = Form(...)):
    user, user_type = authenticate_user(email, password, conn)
    if not user:
       # Handle invalid user or password
        response = templates.TemplateResponse("homepage.html", {"request": request, "msg": "Invalid username or password"})
        return response

    if user_type == 'admin':
        access_token = create_access_token(
        payload={"sub": user[2], "id": user[0], "name": user[1], "type": user_type, "approved": user[4]}
        )
    elif user_type =='vendor':
        access_token = create_access_token(
        payload={"sub": user[2], "id": user[0], "name": user[1], "type": user_type, "approved": user[7]}
        )
    else:
        access_token = create_access_token(
        payload={"sub": user[2], "id": user[0], "name": user[1], "type": user_type}
        )
        cart_items = request.cookies.get("cart_items")
        if cart_items:
            cart_items = json.loads(cart_items)
            c = conn.cursor()
        for item in cart_items:
            c.execute("INSERT INTO cart (customer_id, product_id, quantity) VALUES (?,?,?)", (user[0], item['product_id'], item['quantity']))
            conn.commit()
    response = templates.TemplateResponse("homepage.html", {"request": request, "msg": "Login Successful"})
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.delete_cookie("cart_items")
    return response
        

# eCommerce Homepage
@app.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("homepage.html", {"request": request})

# Sign Up For every type of users:
# Admin Sign Up
@app.post("/admin/signup")
async def admin_signup(name: str, email: str, password: str):
    c = conn.cursor()
    # check if email already exists in the table
    c.execute("SELECT email FROM admins WHERE email =?", (email,))
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
    c.execute("INSERT INTO admins (name, email, hashed_password, approved, created_at) VALUES (?,?,?,0,datetime('now'))",
              (name, email, hashed_password))
    conn.commit()
    return {"message": "Admin created successfully"}

# Customer Sign Up
@app.post("/signup/")
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

# Vendor Sign Up
@app.post("/vendors/signup/")
async def vendor_signup(name: str = Form(...), email: str = Form(...), password: str = Form(...), pan_number: str = Form(...), aadhar_number: str = Form(...), pfp: UploadFile = File(...)):
    c = conn.cursor()
    # check if email already exists in the table
    c.execute("SELECT email FROM vendors WHERE email =?", (email,))
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
    # handle pfp upload
    path = "static/uploads/profilepictures"
    if not os.path.exists(path):
        os.makedirs(path)
    filename = pfp.filename
    i = 1
    while os.path.exists(f'{path}/{filename}'):
        name, ext = os.path.splitext(filename)
        filename = f'{name}_{i}{ext}'
        i += 1
    pfp_path = f'{path}/{filename}'
    with open(pfp_path, 'wb') as f:
        f.write(pfp.file.read())

    # store the hashed password, salt, pan_number, aadhar_number, approved, created_at, and pfp_path in the vendors table
    c.execute("INSERT INTO vendors (name, email, hashed_password, pan_number, aadhar_number, approved, created_at, pfp) VALUES (?,?,?,?,?,0,datetime('now'),?)",
              (name, email, hashed_password, pan_number, aadhar_number, pfp_path))
    conn.commit()
    return {"message": "Vendor created successfully"}

@app.get("/customer-page")
async def customer_page(request: Request):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
# The things that an admin can do
# Adding categories
@app.get("/add-category/")
async def addCategoryGet(request: Request):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'admin':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM categories")
    categories = c.fetchall()
    return templates.TemplateResponse("/admins/categories.html", {"request": request, "categories": categories})

@app.post("/add-category/")
async def addCategoryPost(request: Request, name: str, description: str):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'admin':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("INSERT INTO categories (name, description) VALUES (?,?)", (name, description))
    conn.commit()
    return {"category_id": c.lastrowid, "message": "Category added successfully"}

# Approving or deleting vendors
@app.get("/vendors/")
async def view_vendors(request: Request):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'admin':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM vendors")
    vendors = c.fetchall()
    return {"vendors": vendors}

@app.post("/vendors/{vendor_id}/approve/")
async def approve_vendor(request: Request, vendor_id: int):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'admin':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM vendors WHERE id =?", (vendor_id,))
    vendor = c.fetchone()
    if not vendor:
        raise HTTPException(
            status_code=404,
            detail="Vendor not found"
        )
    c.execute("UPDATE vendors SET approved = 1 WHERE id =?", (vendor_id,))
    conn.commit()
    return {"message": "Vendor approved successfully"}

@app.delete("/vendors/{vendor_id}/delete/")
async def delete_vendor(request: Request, vendor_id: int):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'admin':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM vendors WHERE id =?", (vendor_id,))
    vendor = c.fetchone()
    if not vendor:
        raise HTTPException(
            status_code=404,
            detail="Vendor not found"
        )
    c.execute("DELETE FROM vendors WHERE id =?", (vendor_id,))
    conn.commit()
    return {"message": "Vendor deleted successfully"}

# The Things A Vendor Can Do
def generate_product_url(product_name: str, id:int, category_id:int) -> str:
    product_name = re.sub(r'[^A-Za-z0-9]+', ' ', product_name)
    product_name = product_name.lower()
    product_name = product_name.replace(" ", "-")
    url = f"{product_name}-{id}-{category_id}"
    return url
@app.post("/add-product/")
async def add_product(request: Request, product_name: str = Form(...), description: str = Form(...), price: float = Form(...), stock: int = Form(...), category_id: int = Form(...), images: List[UploadFile] = File(...)):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'vendor':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM vendors WHERE email =?", (payload['sub'],))
    vendor = c.fetchone()
    c.execute("INSERT INTO products (product_name, description, price, stock, category_id, vendor_id) VALUES (?,?,?,?,?,?)", (product_name, description, price, stock, category_id, vendor[0]))
    conn.commit()
    product_id = c.lastrowid
    url = generate_product_url(product_name, product_id, category_id)
    c.execute("UPDATE products SET url = ? WHERE id =?", (url, product_id))
    conn.commit()
    for image in images:
        # handle image upload
        path = "static/uploads/productpictures"
        if not os.path.exists(path):
            os.makedirs(path)
        filename = image.filename
        i = 1
        while os.path.exists(f'{path}/{filename}'):
            name, ext = os.path.splitext(filename)
            filename = f'{name}_{i}{ext}'
            i += 1
        image_path = f'{path}/{filename}'
        with open(image_path, 'wb') as f:
            f.write(image.file.read())
        c.execute("INSERT INTO product_images (product_id, image_url) VALUES (?,?)", (product_id, image_path))
        conn.commit()
    return {"product_id": product_id, "message": "Product added successfully"}

# update product details
@app.post("/update-product/{product_id}")
async def update_product(request: Request, product_id: int, product_name: str = Form(...), description: str = Form(...), price: float = Form(...), stock: int = Form(...)):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'vendor':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM vendors WHERE email =?", (payload['sub'],))
    vendor = c.fetchone()
    c.execute("UPDATE products SET product_name = ?, description = ?, price = ?, stock = ? WHERE id = ? AND vendor_id = ?", (product_name, description, price, stock, product_id, vendor[0]))
    conn.commit()
    return {"product_id": product_id, "message": "Product updated successfully"}

@app.post("/add-product-image/{product_id}")
async def add_product_image(request: Request, product_id: int, image: UploadFile = File(...)):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'vendor':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM products WHERE id =?", (product_id,))
    product = c.fetchone()
    if product is None:
        raise HTTPException(
            status_code=404,
            detail="Product not found"
        )
    c.execute("SELECT * FROM vendors WHERE email =?", (payload['sub'],))
    vendor = c.fetchone()
    if product[7] != vendor[0]:
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    # handle image upload
    path = "static/uploads/productpictures"
    if not os.path.exists(path):
        os.makedirs(path)
    filename = image.filename
    i = 1
    while os.path.exists(f'{path}/{filename}'):
        name, ext = os.path.splitext(filename)
        filename = f'{name}_{i}{ext}'
        i += 1
    image_path = f'{path}/{filename}'
    with open(image_path, 'wb') as f:
        f.write(image.file.read())
    c.execute("INSERT INTO product_images (product_id, image_url) VALUES (?,?)", (product_id, image_path))
    conn.commit()
    return {"product_id": product_id, "message": "Product Image added successfully"}


    # Deletes one image from product_images
@app.post("/delete-product-image/{image_id}")
async def delete_product_image(image_id: int, request: Request):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'vendor':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    c.execute("SELECT * FROM product_images WHERE id =?", (image_id,))
    image = c.fetchone()
    if not image:
        raise HTTPException(
            status_code=404,
            detail="Image not found"
        )
    c.execute("DELETE FROM product_images WHERE id =?", (image_id,))
    conn.commit()
    # Delete the image from the server
    os.remove(image[2])
    return {"message": "Image deleted successfully"}

# Delete a product
@app.post("/delete-product/{product_id}")
async def delete_product(product_id: int, request: Request):
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload['type'] != 'vendor':
        raise HTTPException(
            status_code=403,
            detail="Access Forbidden"
        )
    c = conn.cursor()
    # Delete associated images
    c.execute("SELECT image_url FROM product_images WHERE product_id =?", (product_id,))
    images = c.fetchall()
    for image in images:
        os.remove(image[0])
    c.execute("DELETE FROM product_images WHERE product_id =?", (product_id,))
    conn.commit()
    # Delete product_images from the database
    c.execute("SELECT * FROM products WHERE id =?", (product_id,))
    product = c.fetchone()
    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found"
        )
    c.execute("DELETE FROM products WHERE id =?", (product_id,))
    conn.commit()
    return {"message": "Product and associated images deleted successfully"}

# The things that a customer can do
@app.post("/add-to-cart/")
async def add_to_cart(request: Request, product_id: int = Form(...), quantity: int = Form(...)):
    token = request.cookies.get("access_token")
    cart_items = request.cookies.get("cart_items")
    if token:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload['type'] == 'customer':
            c = conn.cursor()
            c.execute("SELECT * FROM products WHERE id =?", (product_id,))
            product = c.fetchone()
            if not product:
                raise HTTPException(
                status_code=404,
                detail="Product not found"
            )
            c.execute("SELECT * FROM cart WHERE customer_id =? and product_id =?", (payload['id'],product_id,))
            cart_item = c.fetchone()
            if cart_item:
                new_quantity = cart_item[3] + quantity
                c.execute("UPDATE cart SET quantity = ? WHERE id =?", (new_quantity, cart_item[0]))
            else:
                c.execute("INSERT INTO cart (customer_id, product_id, quantity) VALUES (?,?,?)", (payload['id'], product_id, quantity))
            conn.commit()
            return {"product_id": product_id, "quantity": quantity, "message": "Product added to cart successfully"}
    else:
        if cart_items:
            cart_items = json.loads(cart_items)
            for item in cart_items:
                if item['product_id'] == product_id:
                    item['quantity'] += quantity
                    break
            else:
                cart_items.append({"product_id": product_id, "quantity": quantity})
        else:
            cart_items = [{"product_id": product_id, "quantity": quantity}]
    response = RedirectResponse("/cart/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="cart_items", value=json.dumps(cart_items), httponly=True)
    return response

@app.get("/cart/")
async def view_cart(request: Request):
    token = request.cookies.get("access_token")
    if token:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload['type'] == 'customer':
            c = conn.cursor()
            c.execute("""
                SELECT p.product_name, p.price, p.stock, c.quantity, pi.image_url
                FROM products p
                JOIN cart c ON c.product_id = p.id
                JOIN product_images pi ON pi.product_id = p.id
                WHERE c.customer_id = ? 
                GROUP BY c.id
                """, (payload['id'],))
            products = c.fetchall()
            cart_items = []
            for item in products:
                stock_status = "In stock" if item[2] > 0 else "Out of stock"
                cart_items.append({
                    "product_name": item[0],
                    "price": item[1],
                    "stock_status": stock_status,
                    "quantity": item[3],
                    "image_url": item[4],
                })
            return {"cart_items": cart_items}
    else:
        cart_items = request.cookies.get("cart_items")
        if cart_items:
            cart_items = json.loads(cart_items)
            products = []
            for item in cart_items:
                c = conn.cursor()
                c.execute("""
                    SELECT p.product_name, p.price, p.stock, c.quantity, pi.image_url
                    FROM products p
                    JOIN cart c ON c.product_id = p.id
                    JOIN product_images pi ON pi.product_id = p.id
                    WHERE c.product_id = ?
                    LIMIT 1
                    """, (item['product_id'],))
                product = c.fetchone()
                if product:
                    stock_status = "In stock" if product[2] > 0 else "Out of stock"
                    products.append({
                        "product_name": product[0],
                        "price": product[1],
                        "stock_status": stock_status,
                        "quantity": item['quantity'],
                        "image_url": product[4],
                        })
        return {"cart_items": products}
def generate_order_number():
    current_time = datetime.now().strftime("%s")
    random_number = random.randint(1000000000, 9999999999)
    order_number = int(str(current_time) + str(random_number))
    return order_number
@app.post("/place-order/")
async def place_order(request: Request, address: Optional[str] = Form(None)):
    token = request.cookies.get("access_token")
    if token:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload['type'] == 'customer':
            c = conn.cursor()
            c.execute("SELECT * FROM customer_addresses WHERE customer_id =? and type = 'primary'", (payload['id'],))
            customer_address = c.fetchone()
            if not customer_address:
                # Redirect to /customer/add-details/ where they can update their details
                return RedirectResponse("/customer/add-details/", status_code=status.HTTP_302_FOUND)
            elif customer_address:
                # Redirect to /customer/select-address/ where they can select the address where they want their order delivered
                return RedirectResponse("/customer/select-address/", status_code=status.HTTP_302_FOUND)
                # The customer selects "proceed to buy button" sending the address to this endpoint.
            if address:
                c.execute("SELECT * FROM cart WHERE customer_id =?", (payload['id'],))
                cart_items = c.fetchall()
                if not cart_items:
                    raise HTTPException(
                    status_code=404,
                    detail="Cart is empty"
                    )
                # calculate the total amount and store it into orders
                total_amount = 0
                for item in cart_items:
                    c.execute("SELECT price FROM products WHERE id =?", (item[2],))
                    price = c.fetchone()
                    total_amount += price[0] * item[3]

                order_number = generate_order_number()
                c.execute("INSERT INTO orders (order_number, customer_id, total_amount, order_status, created_at, address) VALUES (?,?,?,?,?,?)", (order_number, payload['id'], total_amount, 'pending', datetime.now(), address))
                conn.commit()
                c.execute("SELECT id FROM orders WHERE order_number =?", (order_number,))
                order_id = c.fetchone()[0]

                for item in cart_items:
                    c.execute("INSERT INTO order_items (order_id, product_id, quantity) VALUES (?,?,?)", (order_id, item[2], item[3]))
                    c.execute("UPDATE products SET stock = stock - ? WHERE id =?", (item[3], item[2]))
                conn.commit()
                response = RedirectResponse("/order/success/", status_code=status.HTTP_302_FOUND)
                response.delete_cookie("cart_items")
                return response
    else:
        raise HTTPException(
            status_code=401,
            detail="You need to signup and login first!"
        )
