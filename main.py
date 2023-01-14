from fastapi import FastAPI, Request, File, UploadFile, Form
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


# App And Middlewares
app = FastAPI()
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Folder/Directory where static files are going to be stored
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates/Pages to be stored in this folder/directory
templates = Jinja2Templates(directory="templates")

# eCommerce Homepage
@app.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("homepage.html", {"request": request})