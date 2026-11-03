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

        # Run Java program for basic character flags & length
        process = subprocess.Popen(
            ["java", "EntropyTest"],
            cwd=BASE_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Pass password via stdin with a timeout guard
        try:
            stdout, stderr = process.communicate(input=password + "\n", timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            return jsonify({"error": "Processing timeout exceeded."}), 408
        
        if process.returncode != 0:
            return jsonify({"error": "Internal processing error"}), 500

        lines = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
        if len(lines) < 7:
            return jsonify({"error": "Invalid output format"}), 500

        has_lower = lines[2].lower() == 'true'
        has_upper = lines[3].lower() == 'true'
        has_digit = lines[4].lower() == 'true'
        has_symbol = lines[5].lower() == 'true'
        length = int(lines[6])

        # Smart Pattern & Dictionary Analysis (zxcvbn)
        zx_result = zxcvbn
