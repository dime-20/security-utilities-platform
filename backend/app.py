from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import bcrypt

from utils.token_generator import generate_token
from utils.password_strength import (
    calculate_entropy,
    crack_time_from_entropy,
    score_from_entropy
)

print("### SECURITY SUITE BACKEND LOADED ###")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})


# -----------------------------
# RATE LIMITER
# -----------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

# -----------------------------
# PASSWORD GENERATOR (FORMER TOKEN GENERATOR)
# -----------------------------
@app.route("/api/token", methods=["POST", "OPTIONS"])
@cross_origin
@limiter.limit("10 per minute")
def token_api():
    data = request.get_json(silent=True) or {}

    try:
        length = int(data.get("length", 16))
        charset = data.get("charset", "letters")

        # 🔐 SECURITY ENFORCEMENT
        if length < 8 or length > 64:
            return jsonify({
                "error": "Password length must be between 8 and 64"
            }), 400

        token = generate_token(length, charset)

        return jsonify({
            "token": token
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 400


# --------------------------------
# PASSWORD STRENGTH CHECKER
# --------------------------------
@app.route("/api/password-strength", methods=["POST", "OPTIONS"])
@cross_origin()
def password_strength_api():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password required"}), 400

    entropy = calculate_entropy(password)
    score = score_from_entropy(entropy)
    crack_time = crack_time_from_entropy(entropy)

    return jsonify({
        "score": score,
        "entropy": entropy,
        "crack_time": crack_time
    })


# -----------------------------
# HASH GENERATOR
# -----------------------------
@app.route("/api/hash", methods=["POST", "OPTIONS"])
@cross_origin()
@limiter.limit("5 per minute")
def generate_hash():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    algorithm = data.get("algorithm", "")

    if not text or not algorithm:
        return jsonify({"error": "Invalid input"}), 400

    if algorithm == "md5":
        hashed = hashlib.md5(text.encode()).hexdigest()

    elif algorithm == "sha256":
        hashed = hashlib.sha256(text.encode()).hexdigest()

    elif algorithm == "bcrypt":
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(text.encode(), salt).decode()

    else:
        return jsonify({"error": "Unsupported algorithm"}), 400

    return jsonify({
        "algorithm": algorithm.upper(),
        "hash": hashed
    })


# -----------------------------
# RATE LIMIT ERROR HANDLER
# -----------------------------
@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please slow down."
    }), 429


# -----------------------------
# ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

