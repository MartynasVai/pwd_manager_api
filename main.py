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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

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
userdata_collection = db['PASSWORDDATA']
#collection = db["TEST"]
# The data to be added
#data = {"message": "HELLO world"}
# Insert the data into the collection
#collection.insert_one(data)

def hash_with_pepper(password,pepper):

    hashed_password = hashlib.pbkdf2_hmac('sha256', password, pepper.encode('utf-8'), 100000)


    return hashed_password



def decode_base64(encoded_data):
    # Add extra padding to make the length a multiple of 4
    padding_length = len(encoded_data) % 4
    encoded_data += '=' * ((4 - padding_length) % 4)

    # Decode URL-safe base64 with automatic padding
    try:
        decoded_data = base64.urlsafe_b64decode(encoded_data)
        return decoded_data
    except Exception as e:
        print(f"Error decoding base64: {e}")
        return None

def encode_base64(data):
    # Encode using URL-safe base64
    encoded_data = base64.urlsafe_b64encode(data)
    return encoded_data  # Convert bytes to string

#set session time to 10 minutes
app = Flask(__name__)
@app.route('/login', methods=['GET'])
def login():
    # Get parameters from the request
    action = request.args.get('action')
    username = request.args.get('username')

    # Check for invalid login attempts
    #if invalid_login(username):
    #    return jsonify({'message': 'Too many invalid login attempts. Try again later.'}), 403

    if action == 'get_salt':
        # Retrieve password_salt from MongoDB based on the username
        user_data = usercollection.find_one({'username': username})
        if user_data:
            password_salt = user_data.get('password_salt')
            base64_encoded_password_salt = encode_base64(password_salt).decode('utf-8')
            return jsonify({'password_salt': base64_encoded_password_salt}), 200
        else:
            return jsonify({'message': 'User not found'}), 404

    elif action == 'check_hash':
        # Get parameters from the request
        password_hash = request.args.get('password_hash')
        password_hash = decode_base64(password_hash)
        print(password_hash)
        print("/n\n ^^^^^ password hash ")
        password_hash = hash_with_pepper(password_hash,PEPPER)
        print(password_hash)
        print("/n\n ^^^^^ password hash ")
        # Retrieve password_hash from MongoDB based on the username
        user_data = usercollection.find_one({'username': username, 'password_hash': password_hash})
        if user_data:
            # If password hash is correct, reset invalid login attempts
            #reset_invalid_login(username)

            encrypted_private_key = user_data.get('encrypted_private_key')
            iv = user_data.get('iv')
            salt = user_data.get('salt')
            public_key = user_data.get('public_key')

            # Base64 encode the parameters
            encrypted_private_key_b64 = encode_base64(encrypted_private_key).decode('utf-8')
            iv_b64 = encode_base64(iv).decode('utf-8')
            salt_b64 = encode_base64(salt).decode('utf-8')
            public_key_b64 = encode_base64(public_key).decode('utf-8')

            return jsonify({
                'encrypted_private_key': encrypted_private_key_b64,
                'iv': iv_b64,
                'salt': salt_b64,
                'public_key': public_key_b64
            }), 200
        else:
            # Increment invalid login attempts
            #increment_invalid_login(username)
            return jsonify({'message': 'Invalid credentials'}), 401

    elif action == 'verify':###########################################################################TODO: FINISH LOGIN
        # Get parameters from the request
        #signed_message = decode_base64(request.args.get('signed_message'))
        signature = request.args.get('signature')
        # Retrieve public_key from MongoDB based on the username
        user_data = usercollection.find_one({'username': username})
        if user_data:
            public_key = user_data.get('public_key')

            # Verify the signed message using the public key
            print(username.encode('utf-8'))
            if verify_signature(public_key, signature, username):
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

def verify_signature(public_key_bytes, signature, message):
    
    print(signature)
    #public_key_bytes=b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvsnmUM0ZDplkMoFEiDGb\npyyKHEWRaImPuIWaKMQgQN2rHZEgExw4W3SimbWSC1L/jwjFw+xm1ogmKgZfr55j\nhD9cajJjTALn9FnYxnsPEMk5vF0vbbC7Xc0ZPrMastyvM52TUoSudBv1QYFTRhew\ns0QQCrkhHLdWL11ISJPXqbey5Yp9f3RgHBY/xliHEncBZRzmOgUIPHg2aTmpcBlj\nH0rbCkO3oJULeY9hadVUU1geeNjTP6x50RDxw7im3zaMdzB9I5Ip+8dx3oKOhXwd\nnb9DDC5enCoHo+weIe8wPbJm5EjHu/UStHwIs/r55WjadLGnBQsXWuMFAHLsRD9A\nAQIDAQAB\n-----END PUBLIC KEY-----\n"
    #signature=b"YBFhamA9Es3cgRBOfodx02D50MamWHvfj4xbeUzc/6oP9Ib+RqBT1cb+sUeIM5qBtJm4y4q6NV1F6OyDej/xolAwecQGs1i8DKjZn2Nz/zEkX3pyDPXe2IUqFPR8ksCcadQohwqcfMJGi3wrmEnByxrKaL38lzlbkoaZkYkVZJH/uaQe1VwaQsSjfKKxmClw3eqviYfkJlcDP6gizZocQatRHpN3FftdAL0eGCETN9fxDT53ACM4f8X5+8Jbn1lhVUuXGWWADYMT488Beo9LXfzn3PJNOVNm9pKxGn+AtDKULRp2027EZu8k6xH1AY+aukBYlYm+fz3bph9DFQzQxQ=="
    signature = decode_base64(signature)
    print(signature)
    #message="my_username"
    try:
        public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
        )
        
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature verified successfully.")
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False
    

@app.route('/saveinfo', methods=['POST'])
def save_info():
    try:
        # Get the JSON data from the request
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str)

        verification = data.get('verification')
        creator_username = data.get('creator_username')
        title = data.get('title')
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        print(creator_username)
        user_data = usercollection.find_one({'username': creator_username})
        print("2")
        if user_data:
            print("3")
            public_key = user_data.get('public_key')
            # Verify the signed message using the public key
            print(username.encode('utf-8'))
            if verify_signature(public_key, verification, creator_username):
            
                # Check if a record with the same creator_username and title already exists
                existing_record = userdata_collection.find_one({
                    'creator_username': creator_username,
                    'title': title
                })

                if existing_record:
                    return jsonify({"error": "Title must be unique"}), 400

                # Creating a login_info record
                login_info = {
                    'creator_username': creator_username,
                    'title': title,
                    'username': username,
                    'password': password,
                    'email': email
                }

                # Inserting the record into the userdata collection
                result = userdata_collection.insert_one(login_info)

                if result.inserted_id:
                    return jsonify({"message": "Data saved successfully"}), 200
                else:
                    return jsonify({"message": "Failed to save data1"}), 500

            else:
                return jsonify({"message": "Failed to save data2"}), 500
        else:
            return jsonify({"message": "Failed to save data3"}), 500
    except Exception as e:
                return jsonify({"error": str(e)}), 500
    
@app.route('/read_info', methods=['POST'])
def read_info():
    try:
        print("1")
        json_data = request.get_json()

        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str)

        verification = data.get('verification')
        username = data.get('username')
        user_data = usercollection.find_one({'username': username})
        if user_data:
            print("a")
            print("\n\n\n\n\n\n\n\nHERE1")
            public_key = user_data.get('public_key')
            print("\n\n\n\n\n\n\n\nheressssssssssssssssssssssssssss2")
            # Verify the signed message using the public key
            print(username.encode('utf-8'))
            if verify_signature(public_key, verification, username):
                print("\n\n\n\n\n\n\n\nVERIFIED")
                data_records = userdata_collection.find({'creator_username': username})
                # Convert MongoDB cursor to a list of dictionaries
                data_list = list(data_records)

                # Encode specific fields in Base64
                for record in data_list:
                    if 'field_to_encode' in record:
                        record['field_to_encode'] = base64.b64encode(record['password'].encode('utf-8')).decode('utf-8')
                    elif '_id'in record:
                        record['_id'] = str(record['_id'])

                # Return the data as JSON
                return jsonify({"data": data_list}), 200



            else:
                return jsonify({"message": "Failed to read data3"}), 500

        else:
            return jsonify({"message": "Failed to read data3"}), 500
    except Exception as e:
        print("Signature verification failed:", e)
        return jsonify({"message": "Failed to verify"}), 500
    pass




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

    print(password_salt)
    print("/n\n ^^^^^ password hash ")


    print(password_hash)
    print("/n\n ^^^^^ password hash ")

    password_hash=hash_with_pepper(password_hash,PEPPER)
    print(password_hash)
    print("/n\n ^^^^^ password hash ")

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