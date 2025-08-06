from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
from functools import wraps
import os
import jwt

app = Flask(__name__)
CORS(app)

#check for JWT key
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'defaultkey')

# Connect to MongoDB Atlas
client = MongoClient(os.environ['MONGO_URI'])
db = client.tasktracker
tasks_collection = db.tasks
users_collection = db.users

#JWT authenticates user
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            #strip 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            #decode the token
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": False})
            current_user_id = payload['user_id']
            
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user_id, *args, **kwargs)
    return decorated

#register user
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]

    #check if user already exists
    existing_user = users_collection.find_one({"username": username})
    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    #create new user and generate id
    result = users_collection.insert_one({"username": username, "password": password})
    return jsonify({"_id": str(result.inserted_id)}), 201

#login user
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    #check if user exists with given credentials
    user = users_collection.find_one({"username": username, "password": password})
    if user:
        token = jwt.encode(
                {"user_id": str(user["_id"])}, 
                app.config["JWT_SECRET_KEY"], 
                algorithm="HS256"
                )

        return jsonify({
        "_id": str(user["_id"]),
        "username": user["username"],
        "token": token
        }), 200

    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/tasks", methods=["GET"])
@jwt_required
def get_tasks(user_id):
    tasks = list(tasks_collection.find({'user_id': user_id}))
    for task in tasks:
        task["_id"] = str(task["_id"])
    return jsonify(tasks)

@app.route("/tasks", methods=["POST"])
@jwt_required
def add_task(user_id):
    data = request.json
    result = tasks_collection.insert_one({
        "title": data["title"], 
        "completed": False,
        "user_id": user_id
    })
    return jsonify({"_id": str(result.inserted_id)})

@app.route("/tasks/<task_id>", methods=["DELETE"])
@jwt_required
def delete_task(user_id, task_id):
    result = tasks_collection.delete_one({
        "_id": ObjectId(task_id),
        "user_id": user_id
    })
    return jsonify({"deleted": result.deleted_count > 0})

@app.route("/tasks/<task_id>", methods=["PUT"])
@jwt_required
def update_task(user_id, task_id):
    data = request.json
    #Only update if task belongs to user
    result = tasks_collection.update_one(
        {"_id": ObjectId(task_id), "user_id": user_id},
        {"$set": data}
    )
    return jsonify({"updated": result.modified_count > 0})


@app.route("/")
def index():
    return "Backend is running. Try /tasks"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
