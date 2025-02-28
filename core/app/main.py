from fastapi import FastAPI

from app.routers import user

app = FastAPI(root_path="/")


app.include_router(user.router)
