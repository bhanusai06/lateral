import os, traceback
from dotenv import load_dotenv
load_dotenv()
from flask import Flask
from flask_pymongo import PyMongo

app = Flask('test')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
print("Connecting to:", app.config['MONGO_URI'])

try:
    mongo = PyMongo(app)
    print("PyMongo initialized. DB:", mongo.db.name)
    user = mongo.db.users.find_one({"username": "test"})
    print("Find result:", user)
except Exception as e:
    print("FAILED!")
    traceback.print_exc()
