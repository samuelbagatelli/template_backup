from fastapi import FastAPI

from app.routers import user

app = FastAPI(root_path="/")


@app.get("")
async def hello():
    return "Hello World"


app.include_router(user.router)
