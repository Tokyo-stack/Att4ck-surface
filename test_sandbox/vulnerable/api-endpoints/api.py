from fastapi import FastAPI
app = FastAPI()

@app.get("/api/orders")
def list_orders():
    return db.all_orders()
