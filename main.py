from flask import Flask, jsonify, redirect, url_for
from flask_dance.contrib.google import make_google_blueprint, google
import os

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.getenv("google_client_id")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.getenv("google_client_secret")
app.config["OAUTHLIB_INSECURE_TRANSPORT"] = 1 #HTTP INSTEAD OF HTTPS !!!!!!!!!!!!!!!!!!!!!!!

google_bp = make_google_blueprint(scope=["profile", "email"])
app.register_blueprint(google_bp, url_prefix="/login")

@app.route('/')
def index():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v1/userinfo")
    return jsonify(resp.json())

if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
