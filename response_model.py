#activity
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# --- Request/Response Models ---
class User(BaseModel):
    name: str
    age: int

# This model extends User and adds extra fields for the response
class UserResponse(User):
    message: str
    status: str

# --- API Endpoint ---
@app.get("/user", response_model=UserResponse)
def get_user():
    # Core user data
    user_data = {
        "name": "Deepu",
        "age": 22
    }

    # Additional data to include in response
    extra_data = {
        "message": "User data fetched successfully",
        "status": "Success"
    }

    # Merge both and return
    return {**user_data,**extra_data}