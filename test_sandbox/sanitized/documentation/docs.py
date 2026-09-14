import os
from fastapi import FastAPI
_prod = os.environ.get("ENV") == "production"
app = FastAPI(docs_url=None if _prod else "/docs", redoc_url=None, openapi_url=None if _prod else "/openapi.json")
