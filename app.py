
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from bson import ObjectId
import bcrypt
import jwt
import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "https://cs4843-final-frontend.onrender.com"}})
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
db = mongo.db
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")

# Create indexes for performance
db.users.create_index("username", unique=True)
db.tasks.create_index("user_id")

# Valid task statuses
VALID_STATUSES = ["To Do", "In Progress", "Done"]

# JWT authentication decorator
def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            token = token.replace('Bearer ', '')
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if db.users.find_one({"username": username}):
        return jsonify({"error": "Username already exists"}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    try:
        user_id = db.users.insert_one({
            "username": username,
            "password": hashed_password
        }).inserted_id
        return jsonify({"message": "User registered successfully", "user_id": str(user_id)}), 201
    except Exception as e:
        return jsonify({"error": "Failed to register user: database error"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = db.users.find_one({"username": username})
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        token = jwt.encode({
            'user_id': str(user['_id']),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({"message": "Login successful", "token": token, "user_id": str(user['_id'])}), 200
    return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description', '')
    status = data.get('status', 'To Do')
    
    if not title:
        return jsonify({"error": "Title is required"}), 400
    if status not in VALID_STATUSES:
        return jsonify({"error": f"Status must be one of {VALID_STATUSES}"}), 400
    
    try:
        task_id = db.tasks.insert_one({
            "user_id": ObjectId(current_user),
            "title": title,
            "description": description,
            "status": status,
            "created_at": datetime.datetime.utcnow(),
            "updated_at": datetime.datetime.utcnow()
        }).inserted_id
        return jsonify({"message": "Task created successfully", "task_id": str(task_id)}), 201
    except Exception as e:
        return jsonify({"error": "Failed to create task: database error"}), 500

@app.route('/api/tasks/<user_id>', methods=['GET'])
@token_required
def get_tasks(current_user, user_id):
    if current_user != user_id:
        return jsonify({"error": "Unauthorized access"}), 403
    
    status_filter = request.args.get('status')
    sort_by = request.args.get('sort', 'created_at')
    sort_order = 1 if request.args.get('order', 'asc') == 'asc' else -1
    
    query = {"user_id": ObjectId(user_id)}
    if status_filter in VALID_STATUSES:
        query["status"] = status_filter
    
    try:
        tasks = db.tasks.find(query).sort(sort_by, sort_order)
        task_list = [
            {
                "id": str(task['_id']),
                "title": task['title'],
                "description": task['description'],
                "status": task['status'],
                "created_at": task['created_at'].isoformat(),
                "updated_at": task['updated_at'].isoformat()
            } for task in tasks
        ]
        return jsonify(task_list), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch tasks: database error"}), 500

@app.route('/api/tasks/<task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')
    
    update_data = {"updated_at": datetime.datetime.utcnow()}
    if title:
        update_data['title'] = title
    if description is not None:
        update_data['description'] = description
    if status and status in VALID_STATUSES:
        update_data['status'] = status
    elif status:
        return jsonify({"error": f"Status must be one of {VALID_STATUSES}"}), 400
    
    try:
        task = db.tasks.find_one({"_id": ObjectId(task_id), "user_id": ObjectId(current_user)})
        if not task:
            return jsonify({"error": "Task not found or unauthorized"}), 404
        result = db.tasks.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": update_data}
        )
        if result.modified_count > 0:
            return jsonify({"message": "Task updated successfully"}), 200
        return jsonify({"error": "No changes made"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to update task: database error"}), 500

@app.route('/api/tasks/<task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    try:
        task = db.tasks.find_one({"_id": ObjectId(task_id), "user_id": ObjectId(current_user)})
        if not task:
            return jsonify({"error": "Task not found or unauthorized"}), 404
        result = db.tasks.delete_one({"_id": ObjectId(task_id)})
        if result.deleted_count > 0:
            return jsonify({"message": "Task deleted successfully"}), 200
        return jsonify({"error": "Task not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to delete task: database error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
