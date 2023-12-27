from flask import Flask, jsonify, redirect, url_for
import os



app = Flask(__name__)



@app.route('/')
def index():

    return jsonify("NOT LOGGED IN")


if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))