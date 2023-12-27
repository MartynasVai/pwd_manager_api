from flask import Flask, jsonify, redirect, url_for, request
import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import json
import base64
from flask import Flask, jsonify, request
from pymongo import MongoClient
import json
import base64

        # Replace the placeholders with your actual valuess
MONGOHOST = "monorail.proxy.rlwy.net"
MONGOPORT = "55890"
MONGOUSER = "mongo"
MONGOPASSWORD = "ChghdfdGBbChhfCCh-DeDBCd26A53GbC"
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

def decode_base64(encoded_data):
    return base64.b64decode(encoded_data)

app = Flask(__name__)
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