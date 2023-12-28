from flask import Flask, jsonify, redirect, url_for, request, session
import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import json
import base64
from flask import Flask, jsonify, request
from pymongo import MongoClient
import json
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa

        # Replace the placeholders with your actual valuess
MONGOHOST = "monorail.proxy.rlwy.net"
MONGOPORT = "55890"
MONGOUSER = "mongo"
MONGOPASSWORD = "ChghdfdGBbChhfCCh-DeDBCd26A53GbC"
PEPPER = "917fb97bd62f96e619f4da5036f777c4"
# Create a connection string
connection_string = f"mongodb://{MONGOUSER}:{MONGOPASSWORD}@{MONGOHOST}:{MONGOPORT}"
try:
    # Create a MongoClient instance
    client = MongoClient(connection_string)
    # The ismaster command is cheap and does not require auth.
    client.admin.command('ismaster')
    print("Database connection successful.")
except ConnectionFailure:
    print("Database connection failed.")
db = client.mydatabase
usercollection=db["USERS"]
#collection = db["TEST"]
# The data to be added
#data = {"message": "HELLO world"}
# Insert the data into the collection
#collection.insert_one(data)

def hash_with_pepper(password,pepper):

    hashed_password = hashlib.pbkdf2_hmac('sha256', password, pepper.encode('utf-8'), 100000)


    return hashed_password



def decode_base64(encoded_data):
    return base64.b64decode(encoded_data)
#set session time to 10 minutes
app = Flask(__name__)
@app.route('/login', methods=['GET'])
def login():
    # Get parameters from the request
    action = request.args.get('action')
    username = request.args.get('username')

    # Check for invalid login attempts
    if invalid_login(username):
        return jsonify({'message': 'Too many invalid login attempts. Try again later.'}), 403

    if action == 'get_salt':
        # Retrieve password_salt from MongoDB based on the username
        user_data = usercollection.find_one({'username': username})
        if user_data:
            password_salt = user_data.get('password_salt')
            return jsonify({'password_salt': password_salt}), 200
        else:
            return jsonify({'message': 'User not found'}), 404

    elif action == 'check_hash':
        # Get parameters from the request
        password_hash = request.args.get('password_hash')

        # Retrieve password_hash from MongoDB based on the username
        user_data = usercollection.find_one({'username': username, 'password_hash': password_hash})
        if user_data:
            # If password hash is correct, reset invalid login attempts
            reset_invalid_login(username)

            # Retrieve additional data
            encrypted_private_key = user_data.get('encrypted_private_key')
            iv = user_data.get('iv')
            password_salt = user_data.get('password_salt')
            return jsonify({
                'encrypted_private_key': encrypted_private_key,
                'iv': iv,
                'password_salt': password_salt
            }), 200
        else:
            # Increment invalid login attempts
            increment_invalid_login(username)
            return jsonify({'message': 'Invalid credentials'}), 401

    elif action == 'verify':
        # Get parameters from the request
        signed_message = request.args.get('signed_message')

        # Retrieve public_key from MongoDB based on the username
        user_data = usercollection.find_one({'username': username})
        if user_data:
            public_key = user_data.get('public_key')

            # Verify the signed message using the public key
            if verify_signature(public_key, signed_message):
                return jsonify({'message': 'Login attempt successful'}), 200
            else:
                return jsonify({'message': 'Signature verification failed'}), 401
        else:
            return jsonify({'message': 'User not found'}), 404

    else:
        return jsonify({'message': 'Invalid action'}), 400
    #return jsonify("skrr gang gang")
def invalid_login(username):
    # Check if the session variable for the username exists
    if 'invalid_login_count' not in session:
        # If it doesn't exist, initialize it to 0
        session['invalid_login_count'] = {username: 0}

    # Check if the username is present in the session variable
    if username not in session['invalid_login_count']:
        # If it doesn't exist for the current username, initialize it to 0
        session['invalid_login_count'][username] = 0

    # Check if the invalid login count exceeds the threshold (4)
    return session['invalid_login_count'][username] > 4

def increment_invalid_login(username):
    # Increment the invalid login count for the username
    session['invalid_login_count'][username] += 1

def reset_invalid_login(username):
    # Reset the invalid login count for the username
    session['invalid_login_count'][username] = 0

def verify_signature(public_key, signed_message):
    # Verify the signed message using the public key
    #key = RSA.import_key(base64.b64decode(public_key))
    #h = SHA256.new(signed_message.encode('utf-8'))
    #try:
    #    pkcs1_15.new(key).verify(h, base64.b64decode(signed_message))
    #    return True
    #except (ValueError, TypeError, pkcs1_15.VerificationError):
    #    return False
    return True




@app.route('/getkey/')
def getkey():
    # Return the public key as part of a JSON response
    return jsonify({'PUBLIC_KEY': PUBLIC_KEY})

@app.route('/register', methods=['POST'])
def register():
    # Get the JSON data from the request
    json_data = request.get_json()

    # Extract user data from JSON
    json_data_str = json_data.get('json_data')
    user_data = json.loads(json_data_str)

    # Extract fields excluding the password
    username = user_data.get('username')
    email = user_data.get('email')
    salt = decode_base64(user_data.get('salt'))
    iv = decode_base64(user_data.get('iv'))
    public_key = decode_base64(user_data.get('public_key'))
    encrypted_private_key = decode_base64(user_data.get('encrypted_private_key'))
    password_hash = decode_base64(user_data.get('password_hash'))
    password_salt = decode_base64(user_data.get('password_salt'))


    password_hash=hash_with_pepper(password_hash,PEPPER)


    # Check if the username already exists in the database
    existing_user = usercollection.find_one({'username': username})
    if existing_user:
        return jsonify({'message': 'Registration failed. Username already exists.'}), 400

    # Create a new user documentt
    new_user = {
        'username': username,
        'email': email,
        'salt': salt,
        'iv': iv,
        'encrypted_private_key':encrypted_private_key,
        'public_key': public_key,
        'password_hash': password_hash,
        'password_salt': password_salt
    }

    # Insert the new user into the database
    result = usercollection.insert_one(new_user)

    # Check if the insertion was successful
    if result.inserted_id:
        return jsonify({'message': 'Registration successful!'}), 200
    else:
        return jsonify({'message': 'Registration failed. Please try again later.'}), 500

@app.route('/')
def index():
    
    
    return jsonify("skrr gang gang")


if __name__ == '__main__':

    PRIVATE_KEY="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzfDsB+2Gl9367qdSd3wmEYzRN6tkaRbNn9bYK7q2ZjiwKFfqQ1vef1VJ2ceDHM8hgXz7SxQvQQcyK1yrS8t0HRlR/xNPZ/+3pEQkluRbGaLXGHVj9s3j+iajw1/8k335XluT2BsorOnFUpxUvJC2NLooL/jr+Z//By/eirCOwA4px8ULG8moBfBG3+wwhQvWzpygQZB1p2QZDlVKnCB8nImI6+MsX45yXXpIGJe2900zaa62nsKgCUxOLX47qkMu7mA/votfuDOuHjgj+a1/mVIT22hIjY9gac+3NwMUbDIqw69S7z6reV6u0Zt/Ygl73hU0YXTbR6G0k7+7PsDBXAgMBAAECggEAAX06edejtMUFlKLflN2OEEN92MGKNAKjUfTVn5/S2PKJd0TJfZhOU0f6haWzhHkHzIVaKWOY9N9Lt77iJYeKNZgXbnHXfkDGFmNaFFxKfkEC6Mg3GcSGlzUAZV00Nt1eoyf46na2G9+iZKtucpCIG+tyO8VkKx8bUvF1mATt4E564cx/mXeEb9A5IbFJ0P9I9OegUMoXwWZamR2/4oueFwNrp2NJyjOiGoViAw8DwvMHu/3Uz5CN//UWmSHRT9MubXx4rSHMnYryW53Q+VnZnV383WKo2s7VzSrhYcYzVQv7XBsHzyiObscUAKu72y5fD0M498vkH5M23JOOY2aQCQKBgQDunwCdmMzDQ0Rf4a76/lXBhugPlVbqOXm/Kih2HGDtz7hXGIroxj4zpqSo54Mimj8F8RsiNEYiewyNeCENV7QxJdnYbzQ7v9YFC0Cp2EbdqOrmBQi2XNZ65NtHBwHGBjVbMdJ0ZTulg1M+nScXSsjay9R9bGZ/lB+Ii6HgP7m33QKBgQDAjqnhzjVrb2zgajuZGU/Tv75n1R6n+2eMfol23GFW6/JnVTSKV3qA18+uRBwYkk52k4yW3+Iq9vb45mlDrR5loTtdRcIB49tBqYzh+HXHKKUJb7N4NAfQYq0rkkr/AmcM2NaZKa4W9Jhlf5/c5DEKIVwwhfmmQC8gX6KPXCT/wwKBgQC1xxDL/av3EBZVSHJpKDkh3WiI/oYgljpFw5LhLwsz/qp6RusDGoomBMupE/xU7tYV66905geLmttcJehf5rERQ7lpZIWRArnCS+ktueF6WIThR3J0odKN+iuFNzRFq1MYLqMZIklG8/0FVOiDmOfbra0pAtwuUiOXfG+LimArTQKBgGZt/XR+qvABj9s454cjbdFoGDNHrU0ScRzNWvZ9eNIyJPpO2uoUargLFRDQblmryk1NY+YGJltQkEQK3UgA2UCaqeeN6gvzV3jwZl72OkC9ID2Ky99PXjC9rPyWj4pjjsnIty82esL/TeoAH9vzDxsib9XoDssfLXJ9LQ4xqATdAoGAeGZb//nWCMAxXZ7W0HBv1OAfFcB7wChQXvnTZilMh2HjOG+72vP7X70nbaXe9VUmBj0cpEuURm88fRgMzKDoyQy1R0sh8GRdeVqQzswLSyjcoeudzN9fZ8iYAqutfBTZ+kEZC+J1GqqRNZ5tQuyELuZm60qVEod+CezHWeBiAHI="
    PUBLIC_KEY="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3w7Afthpfd+u6nUnd8JhGM0TerZGkWzZ/W2Cu6tmY4sChX6kNb3n9VSdnHgxzPIYF8+0sUL0EHMitcq0vLdB0ZUf8TT2f/t6REJJbkWxmi1xh1Y/bN4/omo8Nf/JN9+V5bk9gbKKzpxVKcVLyQtjS6KC/46/mf/wcv3oqwjsAOKcfFCxvJqAXwRt/sMIUL1s6coEGQdadkGQ5VSpwgfJyJiOvjLF+Ocl16SBiXtvdNM2mutp7CoAlMTi1+O6pDLu5gP76LX7gzrh44I/mtf5lSE9toSI2PYGnPtzcDFGwyKsOvUu8+q3lertGbf2IJe94VNGF020ehtJO/uz7AwVwIDAQAB"




    app.run(debug=True, port=os.getenv("PORT", default=5000))