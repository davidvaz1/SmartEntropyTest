from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from zxcvbn import zxcvbn
import subprocess
import os
import math
import re
import traceback

app = Flask(__name__)

# Setup Rate Limiter to prevent API abuse / DoS
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per minute"],
    storage_uri="memory://"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def format_crack_time(seconds):
    if seconds is None or seconds > 3.1536e16:
        return "Billions of years"
    if seconds < 1:
        return "Instant"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    elif seconds < 31536000 * 1000:
        return f"{int(seconds / 31536000)} years"
    else:
        return f"{int(seconds / (31536000 * 1000))} thousand+ years"

@app.after_request
def add_security_headers(response):
    """Inject robust security headers to protect against web vulnerabilities."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
@limiter.limit("10 per second")
def analyze():
    try:
        data = request.get_json()
        if not data or "password" not in data:
            return jsonify({"error": "Invalid request payload"}), 400
            
        password = data["password"]

        # Input Validation: Enforce type and length bounds
        if not isinstance(password, str) or len(password) > 128:
            return jsonify({"error": "Password must be a string under 128 characters."}), 400

        # Sanitize control characters
        password = re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]', '', password)

        # Run Java program securely with a 2-second timeout guard
        try:
            completed = subprocess.run(
                ["java", "EntropyTest"],
                input=password + "\n",
                cwd=BASE_DIR,
                capture_output=True,
