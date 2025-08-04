from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import os

app = Flask(__name__)
CORS(app)

# Connect to MongoDB Atlas
client = MongoClient(os.environ['MONGO_URI'])
db = client.tasktracker
tasks_collection = db.tasks

@app.route("/tasks", methods=["GET"])
def get_tasks():
    tasks = list(tasks_collection.find())
    for task in tasks:
        task["_id"] = str(task["_id"])
    return jsonify(tasks)

@app.route("/tasks", methods=["POST"])
def add_task():
    data = request.json
    result = tasks_collection.insert_one({"title": data["title"], "completed": False})
    return jsonify({"_id": str(result.inserted_id)})

@app.route("/tasks/<task_id>", methods=["DELETE"])
def delete_task(task_id):
    result = tasks_collection.delete_one({"_id": ObjectId(task_id)})
    return jsonify({"deleted": result.deleted_count > 0})

@app.route("/tasks/<task_id>", methods=["PUT"])
def update_task(task_id):
    data = request.json
    result = tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": data})
    return jsonify({"updated": result.modified_count > 0})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
