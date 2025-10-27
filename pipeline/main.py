from fastapi import FastAPI
from starlette.responses import PlainTextResponse

app = FastAPI()


@app.get("/", response_class=PlainTextResponse)
async def read_root():
    return "Hello, World!"
