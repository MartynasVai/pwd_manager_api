from flask import Flask, jsonify, request, session
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
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from bson import ObjectId
from mailjet_rest import Client

        # Replace the placeholders with your actual valuess
MONGOHOST = "monorail.proxy.rlwy.net"
MONGOPORT = "55890"
MONGOUSER = "mongo"
MONGOPASSWORD = "ChghdfdGBbChhfCCh-DeDBCd26A53GbC"
PEPPER = "917fb97bd62f96e619f4da5036f777c4"
MAILJET = mailjet = Client(auth=('3eb96ef7dc01ee697ec2f668793a7bf7', 'ba3b11bd2523fe769cfb80a54135ba06'))
# Create a connection string
#connection_string = f"mongodb://{MONGOUSER}:{MONGOPASSWORD}@{MONGOHOST}:{MONGOPORT}"
connection_string = f"mongodb+srv://martynasvai263:38baby@cluster0.gwmoddu.mongodb.net/"
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
reminder_collection = db['REMINDERS']
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
            email=user_data.get('email')

            return jsonify({
                'encrypted_private_key': encrypted_private_key_b64,
                'iv': iv_b64,
                'salt': salt_b64,
                'public_key': public_key_b64,
                'email':email
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

@app.route('/create_reminder', methods=['POST'])
def create_reminder(): 
    try:
        # Get the JSON data from the request
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str) 
        verification = data.get('verification')
        creator_username = data.get('creator_username')
        title = data.get('title')
        text = data.get('text')
        date = data.get('date')
        time = data.get('time')
        user_data = usercollection.find_one({'username': creator_username})
        if user_data:
            public_key = user_data.get('public_key')
            user_id = user_data.get['_id']
            # Verify the signed message using the public key
            #print(username.encode('utf-8'))
            if verify_signature(public_key, verification, creator_username):
            
                # Check if a record with the same creator_username and title already exists
                existing_record = reminder_collection.find_one({
                    'creator_id': user_id,
                    'title': title
                })

                if existing_record:
                    return jsonify({"error": "Title must be unique"}), 400

                # Creating a login_info record
                login_info = {
                    'creator_id': user_data.get('_id'),
                    'title': title,
                    'text': text,
                    'date': date,
                    'time': time
                }

                # Inserting the record into the userdata collection
                result = reminder_collection.insert_one(login_info)

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
    

@app.route('/edit_reminder', methods=['POST'])
def edit_reminder():
    try:
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str) 

        verification = data.get('verification')
        creator_id = data.get('creator_id')
        title = data.get('title')
        new_title = data.get('new_title')  # New parameter for the new title
        text = data.get('text')
        date = data.get('date')
        time = data.get('time')
        username= data.get('username')

        creator_id=ObjectId(creator_id)

        print("EDIT1")

        user_data = usercollection.find_one({'_id': creator_id})

        if user_data:
            public_key = user_data.get('public_key')

            # Verify the signed message using the public key
            if verify_signature(public_key, verification, username):
            
                # Check if the original record exists
                existing_record = reminder_collection.find_one({
                    'creator_id': creator_id,
                    'title': title
                })

                if not existing_record:
                    return jsonify({"error": "Original record not found"}), 404

                # Check if the new title is unique (excluding the original record)
                if new_title != title:
                    duplicate_record = reminder_collection.find_one({
                        'creator_id': creator_id,
                        'title': new_title
                    })
                    if duplicate_record:
                        return jsonify({"error": "Title must be unique"}), 400

                # Update the existing record
                result = reminder_collection.update_one(
                    {'creator_id': creator_id, 'title': title},
                    {'$set': {
                        'title': new_title,
                        'text': text,
                        'date': date,
                        'time': time
                    }}
                )

                if result.modified_count > 0:
                    return jsonify({"message": "Reminder updated successfully"}), 200
                else:
                    print("FAIL1")
                    return jsonify({"message": "Failed to update reminder"}), 500
                    

            else:
                print("FAIL2")
                return jsonify({"message": "Failed to update reminder: Verification failed"}), 500
            
        else:
            print("FAIL3")
            return jsonify({"message": "Failed to update reminder: User not found"}), 500
            
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        if user_data:
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
            #print("a")
            #print("\n\n\n\n\n\n\n\nHERE1")
            public_key = user_data.get('public_key')
            #print("\n\n\n\n\n\n\n\nheressssssssssssssssssssssssssss2")
            # Verify the signed message using the public key
            #print(username.encode('utf-8'))
            if verify_signature(public_key, verification, username):
                #print("\n\n\n\n\n\n\n\nVERIFIED")
                data_records = userdata_collection.find({'creator_username': username})
                # Convert MongoDB cursor to a list of dictionaries user_data.get('_id')
                data_list = list(data_records)

                reminder_records = reminder_collection.find({'creator_id':user_data.get('_id')})
                reminder_records=list(reminder_records)
                # Encode specific fields in Base64
                for record in data_list:
                    if 'field_to_encode' in record:
                        record['field_to_encode'] = base64.b64encode(record['password'].encode('utf-8')).decode('utf-8')
                        
                    if '_id'in record:
                        record['_id'] = str(record['_id'])
                #print(reminder_records)
                for record in reminder_records:
                    if '_id'in record:
                        record['_id'] = str(record['_id'])
                    if 'creator_id' in record:
                        record['creator_id'] = str(record['creator_id'])
                #print(reminder_records)

                # Return the data as JSON
                return jsonify({"data": data_list,"reminder_records": reminder_records}), 200



            else:
                return jsonify({"message": "Failed to read data3"}), 500

        else:
            return jsonify({"message": "Failed to read data3"}), 500
    except Exception as e:
        print("Signature verification failed:", e)
        return jsonify({"message": "Failed to verify"}), 500
    pass




#@app.route('/getkey/')
#def getkey():
#    # Return the public key as part of a JSON response
#    return jsonify({'PUBLIC_KEY': PUBLIC_KEY})

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

    #print(password_salt)
    #print("/n\n ^^^^^ password hash ")
#
#
    #print(password_hash)
    #print("/n\n ^^^^^ password hash ")
#
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

@app.route('/edit_info', methods=['POST'])
def edit_info():
    try:
        # Get the JSON data from the request
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str)

        verification = data.get('verification')
        creator_username = data.get('creator_username')
        title = data.get('title')
        original_title = data.get('original_title')  # New parameter for the original title

        user_data = usercollection.find_one({'username': creator_username})

        if user_data:
            public_key = user_data.get('public_key')
            # Verify the signed message using the public key
            if verify_signature(public_key, verification, creator_username):
            
                # Check if the original record exists
                existing_record = userdata_collection.find_one({
                    'creator_username': creator_username,
                    'title': original_title
                })

                if not existing_record:
                    return jsonify({"error": "Original record not found"}), 404

                # Check if the new title is unique (excluding the original record)
                if title != original_title:
                    duplicate_record = userdata_collection.find_one({
                        'creator_username': creator_username,
                        'title': title
                    })
                    if duplicate_record:
                        return jsonify({"error": "Title must be unique"}), 400

                # Update the existing record
                result = userdata_collection.update_one(
                    {'creator_username': creator_username, 'title': original_title},
                    {'$set': {
                        'title': title,
                        'username': data.get('username'),
                        'password': data.get('password'),
                        'email': data.get('email')
                    }}
                )

                if result.modified_count > 0:
                    return jsonify({"message": "Data updated successfully"}), 200
                else:
                    return jsonify({"message": "Failed to update data"}), 500

            else:
                return jsonify({"message": "Failed to update data: Verification failed"}), 500
        else:
            return jsonify({"message": "Failed to update data: User not found"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/delete_info', methods=['POST'])
def delete_info():
    try:
        # Get the JSON data from the request
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str)
        # Extract user data from JSON
        verification = data.get('verification')
        creator_username = data.get('creator_username')
        title = data.get('title')

        # Retrieve the user's public key from the database
        user_data = usercollection.find_one({'username': creator_username})
        print(creator_username)
        if user_data:
            public_key = user_data.get('public_key')

            # Verify the signed message using the public key
            if verify_signature(public_key, verification, creator_username):

                # Delete the record based on the provided creator_username and title
                result = userdata_collection.delete_one({'creator_username': creator_username, 'title': title})


                if result.deleted_count > 0:
                    return jsonify({"message": "Record deleted successfully"}), 200
                else:
                    return jsonify({"error": "No matching record found"}), 404

            else:
                print("verification failed")
                return jsonify({"error": "Failed to delete data: Verification failed"}), 500
        else:
            print("user not found")
            return jsonify({"error": "Failed to delete data: User not found"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/delete_acc', methods=['POST'])
def delete_acc():
    try:
        # Get the JSON data from the request
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str)

        verification = data.get('verification')
        creator_username = data.get('creator_username')

        # Retrieve the user's public key from the database
        user_data = usercollection.find_one({'username': creator_username})

        if user_data:
            public_key = user_data.get('public_key')

            # Verify the signed message using the public key
            if verify_signature(public_key, verification, creator_username):

                # Delete the user account
                user_result = usercollection.delete_one({'username': creator_username})
                
                # Delete all records in userdata_collection with the same creator_username
                userdata_result = userdata_collection.delete_many({'creator_username': creator_username})

                user_id=user_data.get('_id')

                userreminders_result = reminder_collection.delete_many({'creator_id': user_id})

                

                if user_result.deleted_count > 0:
                    return jsonify({"message": "User account and associated records deleted successfully"}), 200
                else:
                    return jsonify({"error": "No matching user account found"}), 404

            else:
                return jsonify({"error": "Failed to delete account: Verification failed"}), 500
        else:
            return jsonify({"error": "Failed to delete account: User not found"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/delete_reminder', methods=['POST'])
def delete_reminder():
    try:
        # Get the JSON data from the request
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str)

        verification = data.get('verification')
        creator_username = data.get('username')
        reminder_id = data.get('_id')

        user_data = usercollection.find_one({'username': creator_username})

        if user_data:
            public_key = user_data.get('public_key')

            # Verify the signed message using the public key
            if verify_signature(public_key, verification, creator_username):
            
                # Delete the record
                result = reminder_collection.delete_one({
                    '_id': ObjectId(reminder_id)
                })

                if result.deleted_count > 0:
                    return jsonify({"message": "Reminder deleted successfully"}), 200
                else:
                    return jsonify({"message": "Failed to delete reminder"}), 500

            else:
                return jsonify({"message": "Failed to delete reminder: Verification failed"}), 500
        else:
            return jsonify({"message": "Failed to delete reminder: User not found"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/edit_acc', methods=['POST'])
def edit_acc():
    try:
        print("edit1")
        # Get the JSON data from the request
        json_data = request.get_json()
        # Extract user data from JSON
        json_data_str = json_data.get('json_data')
        data = json.loads(json_data_str)
        print(data)

        # Extract user data from JSON
        verification = data.get('verification')
        creator_username = data.get('creator_username')
        print(creator_username)


        changed_records = data.get('changed_records')

        # Retrieve the user's public key from the database
        user_data = usercollection.find_one({'username': creator_username})
        
        if user_data:
            print("edit2")
            public_key = user_data.get('public_key')

            # Verify the signed message using the public key
            if verify_signature(public_key, verification, creator_username):
            
                password_hash=decode_base64(data.get('password_hash'))
                password_hash=hash_with_pepper(password_hash,PEPPER)

                # Update user account fields
                result = usercollection.update_one(
                    {'username': creator_username},
                    {'$set': {
                        'username': data.get('username'),
                        'email': data.get('email'),
                        'salt': decode_base64(data.get('salt')),
                        'iv': decode_base64(data.get('iv')),
                        'encrypted_private_key': decode_base64(data.get('encrypted_private_key')),
                        'public_key': decode_base64(data.get('public_key')),
                        'password_hash': password_hash,
                        'password_salt': decode_base64(data.get('password_salt'))
                    }}
                )

                changed_record_data = data.get('changed_record_data')
                if changed_record_data is not None:
                    # Update associated records in userdata_collection
                    for record in changed_record_data:
                        print("\n\n\nRECORD SHOULD CHANGE AAAA\n\n\n")
                        userdata_collection.update_one(
                            {'_id': ObjectId(record['_id'])},
                            {'$set': {
                                'creator_username': record['creator_username'],
                                'password': record['password'],
                            }}
                        )

                if result.modified_count > 0:
                    return jsonify({"message": "User account and associated records updated successfully"}), 200
                else:
                    return jsonify({"error": "Failed to update user account"}), 500

            else:
                return jsonify({"error": "Failed to update account: Verification failed"}), 500
        else:
            return jsonify({"error": "Failed to update account: User not found"}), 500

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500
    
def my_hourly_task():
    print("Checking for overdue reminders...")

    # Get the current date and time
    current_datetime = datetime.now()

    # Retrieve all records from the MongoDB collection
    all_reminders = reminder_collection.find()

    # Filter and print overdue reminders
    for reminder in all_reminders:
        reminder_date = datetime.strptime(reminder["date"], "%Y-%m-%d").date()
        reminder_time = datetime.strptime(reminder["time"], "%H:%M") if "time" in reminder else None

        if (
            reminder_date < current_datetime.date() or
            (reminder_date == current_datetime.date() and reminder_time and reminder_time.time() < current_datetime.time())
        ):
            print("Found:", reminder)
            remind(reminder['creator_id'],reminder['text'],reminder['title'])
            reminder_collection.delete_one({'_id': reminder['_id']})
    
    print("This task runs every hour!")

def remind(userid,text,title):

    user_data = usercollection.find_one({'_id': userid})

    if user_data:
        email = user_data.get('email')

        data = {
            'FromEmail': 'xmartissx@gmail.com',
            'FromName': 'Slaptažodžių valdymo sistema',
            'Subject': 'Priminimas',
            'Text-part': str(text),
            'Html-part': '<h1>'+text+'<h1>',
            'Recipients': [
                {'Email': email}
            ]
        }

        result = mailjet.send.create(data=data)
        print(result.status_code)
        print(result.json())



    pass


# Create a scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(my_hourly_task, 'interval',minutes=1) #hours=1)
@app.route('/')
def index():
    
    
    return jsonify("skrr gang gang")


if __name__ == '__main__':




    scheduler.start()
    app.run(debug=True, port=os.getenv("PORT", default=5000))
    