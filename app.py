import hashlib
import datetime
import json
from flask import Flask, render_template, make_response, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from flask_pymongo import PyMongo
from marvel import Marvel
from keys import PUBLIC_KEY, PRIVATE_KEY

marvel = Marvel(PUBLIC_KEY=PUBLIC_KEY, 
                PRIVATE_KEY=PRIVATE_KEY)

app = Flask(__name__)


jwt = JWTManager(app) # initialize JWTManager
app.config['JWT_SECRET_KEY'] = '21bd7139c8930e60b85d389ec1e12a9d4117728a'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1) # define the life span of the token

client = PyMongo(app, uri="mongodb+srv://Admin:Nada8597@cluster0.q3hlpvd.mongodb.net/flaskdatabase?retryWrites=true&w=majority")

users_collection = client.db["users"]

#GET METHOD

@app.route("/")
def home():
    return "<h1>Hola </h1>"


@app.route("/api/users/", methods=["POST"])
def register():
	new_user = request.get_json() # store the json body request
	new_user["password"] = hashlib.sha256(new_user["password"].encode("utf-8")).hexdigest() # encrpt password
	doc = users_collection.find_one({"username": new_user["username"]}) # check if user exist
	if not doc:
		users_collection.insert_one(new_user)
		return jsonify({'msg': 'User created successfully'}), 201
	else:
		return jsonify({'msg': 'Username already exists'}), 409


@app.route("/api/login", methods=["post"])
def login():
	login_details = request.get_json() # store the json body request
	user_from_db = users_collection.find_one({'username': login_details['username']})  # search for user in database

	if user_from_db:
		encrpted_password = hashlib.sha256(login_details['password'].encode("utf-8")).hexdigest()
		if encrpted_password == user_from_db['password']:
			access_token = create_access_token(identity=user_from_db['username']) # create jwt token
			return jsonify(access_token=access_token), 200

	return jsonify({'msg': 'The username or password is incorrect'}), 401

@app.route("/api/user", methods=["GET"])
@jwt_required()
def profile():
	current_user = get_jwt_identity() # Get the identity of the current user
	user_from_db = users_collection.find_one({'username' : current_user})
	if user_from_db:
		del user_from_db['_id'],user_from_db['password'] # delete data we don't want to return
		return jsonify({'profile' : user_from_db }), 200
	else:
		return jsonify({'msg': 'Profile not found'}), 404

@app.route("/api/searchComics", methods=["GET"])
def comics():
	search_details = request.get_json() # store the json body request

	if search_details['name']:
		characters = marvel.characters

		my_char = characters.all(name= search_details['name'],orderBy="name", limit=80)["data"]["results"]

		for char in my_char:
			print( char["id"], char["name"], char["thumbnail"]["path"], char["comics"]["available"])
	if search_details['title']:
		comics = marvel.comics

		my_comic = comics.all(title= search_details['title'] ,orderBy="title", limit=80)["data"]["results"]

		for comic in my_comic:
			print(comic["id"], comic["title"], comic["thumbnail"]["path"], comic["comics"]["available"])
	
	characters = marvel.characters

	my_char = characters.all(orderBy="name", limit=80)["data"]["results"]
	# print(my_char)

	for char in my_char:
		print(char["id"], char["name"], char["comics"]["available"],char["thumbnail"]["path"])

if __name__ == '__main__':
    app.run(debug=True)