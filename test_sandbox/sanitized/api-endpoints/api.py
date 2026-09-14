from fastapi import FastAPI, Depends
from .auth import get_current_user
app = FastAPI()

@app.get("/api/orders")
def list_orders(user=Depends(get_current_user)):
    return db.orders_for(user)
