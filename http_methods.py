from fastapi import FastAPI,HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import create_engine,text
app=FastAPI()
db_url="mysql+pymysql://root:Deepu%40123@127.0.0.1:3306/authenticate"
engine=create_engine(db_url)
#validator
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username must be 3-50 characters")
    email: str
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")
#response model for adding new user in response body
class UserResponse(BaseModel):
    message: str
    username: str
    email: str
    password:int
    extra_info: dict | None = None
@app.get("/")
def home():
    return {"message": "Connected to MySQL successfully!"}
#add new user with username,mail and password
@app.post("/add_user",response_model=UserResponse)
def add_user(user:UserCreate):
    extra_fields = {k: v for k, v in user.dict().items() if k not in ["username", "email", "password"]}
    try:
        with engine.connect() as connection:
            connection.execute(
                text("INSERT INTO user (username, email, password) VALUES (:username, :email, :password)"),
                user.dict()
            )
            connection.commit()
        return UserResponse(
            message="User added successfully!",
            username=user.username,
            email=user.email,
            password=user.password,
            extra_info=extra_fields
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error adding user: {e}")
#update user details with id
@app.put("/update_user/{user_id}")
def update_user(user_id: int, user:UserCreate):
    with engine.connect() as connection:
        connection.execute(
            text("UPDATE user SET username=:username, email=:email, password=:password WHERE id=:id"),
             {**user.dict(), "id": user_id}
        )
        connection.commit()
    return {"message": f"User {user_id} updated successfully!"}
#read all users or limit users using path parameter
@app.get("/users")
def get_users(limit: int = None):
    with engine.connect() as connection:
        if limit:
            result = connection.execute(
                text("SELECT id, username, email FROM user LIMIT :limit"),
                {"limit": limit}
            )
        else:
            result = connection.execute(
                text("SELECT id, username, email FROM user")
            )
        rows = result.mappings().all()
    return {"data": rows}
#delete user
@app.delete("/delete_user/{user_id}")
def delete_user(user_id: int):
    with engine.connect() as connection:
        connection.execute(
            text("DELETE FROM user WHERE id=:id"),
            {"id": user_id}
        )
        connection.commit()
    return {"message": f"User {user_id} deleted successfully!"}



create database authenticate;
use authenticate;
create table user(
id INT AUTO_INCREMENT PRIMARY KEY,
username VARCHAR(50),
email VARCHAR(100),
password VARCHAR(50)
);
insert into user(username,email,password) values('deepika','deepu@gmail.com',1278);
insert into user(username,email,password) values('harika','hari123@gmail.com',1249);
insert into user(username,email,password) values('sashank','sashank@gmail.com',5340);
insert into user(username,email,password) values('navya','navya@gmail.com',1984);
select * from user;
