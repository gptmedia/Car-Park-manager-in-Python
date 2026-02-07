import os
from functools import wraps
from typing import Any, Dict, List

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    session,
)

from practice import CarPark
from user_manager import UserManager

APP_SECRET = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
DB_PATH = os.environ.get("CARPARK_DB", "carpark.db")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = APP_SECRET

user_manager = UserManager(DB_PATH)
carpark = CarPark.load_from_db(DB_PATH) or CarPark(10)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = session.get("username")
        if not username or not user_manager.is_admin(username):
            return jsonify({"error": "Admin privileges required"}), 403
        return fn(*args, **kwargs)

    return wrapper


def ensure_carpark():
    global carpark
    if carpark is None:
        carpark = CarPark(10)
    return carpark


def serialize_state(user: str) -> Dict[str, Any]:
    park = ensure_carpark()
    parked: List[Dict[str, Any]] = []
    for spot in range(1, park.capacity + 1):
        if spot in park.parked_cars:
            record = dict(park.parked_cars[spot])
            record["spot"] = spot
            parked.append(record)

    return {
        "current_user": user,
        "is_admin": user_manager.is_admin(user),
        "capacity": park.capacity,
        "rate_per_hour": park.rate_per_hour,
        "available_spots": park.available_spots(),
        "parked_cars": parked,
        "transactions": park.transactions[-50:],
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/login")
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if not user_manager.authenticate(username, password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["username"] = username
    return jsonify({"message": "Logged in", "user": username})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.get("/api/state")
@login_required
def state():
    user = session["username"]
    return jsonify(serialize_state(user))


@app.post("/api/setup")
@admin_required
def setup():
    global carpark
    data = request.get_json() or {}
    capacity = data.get("capacity")
    rate = data.get("rate_per_hour", carpark.rate_per_hour)
    try:
        capacity = int(capacity)
        if capacity <= 0:
            raise ValueError
    except Exception:
        return jsonify({"error": "Capacity must be a positive integer"}), 400

    new_rate = float(rate)

    carpark = CarPark(capacity)
    carpark.rate_per_hour = new_rate
    return jsonify({"message": "Car park created", "state": serialize_state(session["username"])})


@app.post("/api/park")
@login_required
def park_car_endpoint():
    park = ensure_carpark()
    data = request.get_json() or {}
    plate = (data.get("plate") or "").strip()
    if not plate:
        return jsonify({"error": "License plate is required"}), 400

    success = park.park_car(plate)
    if not success:
        return jsonify({"error": "Car park is full"}), 400
    return jsonify({"message": "Car parked", "state": serialize_state(session["username"])})


@app.post("/api/remove")
@login_required
def remove_car_endpoint():
    park = ensure_carpark()
    data = request.get_json() or {}
    spot = data.get("spot")
    hours_override = data.get("hours_override")
    amount_override = data.get("amount_override")
    try:
        spot = int(spot)
    except Exception:
        return jsonify({"error": "Spot must be an integer"}), 400

    parsed_hours = None
    parsed_amount = None
    if hours_override is not None and hours_override != "":
        try:
            parsed_hours = float(hours_override)
            if parsed_hours < 0:
                raise ValueError
        except Exception:
            return jsonify({"error": "Hours must be a non-negative number"}), 400
    if amount_override is not None and amount_override != "":
        try:
            parsed_amount = round(float(amount_override), 2)
            if parsed_amount < 0:
                raise ValueError
        except Exception:
            return jsonify({"error": "Amount must be a non-negative number"}), 400

    transaction = park.remove_car(
        spot,
        hours_override=parsed_hours,
        amount_override=parsed_amount,
    )
    if not transaction:
        return jsonify({"error": "Invalid spot"}), 400

    return jsonify(
        {"message": "Car removed", "transaction": transaction, "state": serialize_state(session["username"])}
    )


@app.post("/api/spot/<int:spot>/comments")
@login_required
def update_comments(spot: int):
    park = ensure_carpark()
    data = request.get_json() or {}
    comments = data.get("comments", "")
    if not park.update_comments(spot, comments):
        return jsonify({"error": "Spot is empty or does not exist"}), 404
    return jsonify(
        {
            "message": "Comments updated",
            "state": serialize_state(session["username"]),
        }
    )


@app.post("/api/rate")
@admin_required
def set_rate():
    park = ensure_carpark()
    data = request.get_json() or {}
    rate = data.get("rate_per_hour")
    try:
        rate = float(rate)
        if rate <= 0:
            raise ValueError
    except Exception:
        return jsonify({"error": "Rate must be a positive number"}), 400

    park.rate_per_hour = rate
    return jsonify({"message": "Rate updated", "state": serialize_state(session["username"])})


@app.post("/api/save")
@admin_required
def save_state():
    park = ensure_carpark()
    park.save_to_db(DB_PATH)
    return jsonify({"message": "State saved"})


@app.post("/api/load")
@admin_required
def load_state():
    global carpark
    loaded = CarPark.load_from_db(DB_PATH)
    if not loaded:
        return jsonify({"error": "No saved state found"}), 404
    carpark = loaded
    return jsonify({"message": "State loaded", "state": serialize_state(session["username"])})


@app.get("/api/users")
@admin_required
def list_users():
    return jsonify({"users": user_manager.list_users()})


@app.post("/api/users")
@admin_required
def create_user():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")
    try:
        user_manager.create_user(username, password, role)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"message": "User created"})


@app.post("/api/users/<username>/password")
@admin_required
def change_password(username):
    data = request.get_json() or {}
    new_password = data.get("password")
    try:
        user_manager.change_password(username, new_password)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"message": "Password updated"})


@app.post("/api/account/password")
@login_required
def change_own_password():
    """Allow users to change their own password with current password verification."""
    username = session.get("username")
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json() or {}
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    if not current_password or not new_password:
        return jsonify({"error": "Current password and new password required"}), 400
    
    # Verify current password
    if not user_manager.authenticate(username, current_password):
        return jsonify({"error": "Current password is incorrect"}), 401
    
    try:
        user_manager.change_password(username, new_password)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    
    return jsonify({"message": "Password updated"})


@app.delete("/api/users/<username>")
@admin_required
def delete_user(username):
    try:
        user_manager.delete_user(username)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"message": "User deleted"})


if __name__ == "__main__":
    # Optional SSL support. Set USE_SSL=1 to enable.
    # If SSL_CERT and SSL_KEY are provided they will be used,
    # otherwise Flask will use an adhoc/self-signed cert for development.
    use_ssl = os.environ.get("USE_SSL", "").lower() in ("1", "true", "yes", "on")
    if use_ssl:
        cert = os.environ.get("SSL_CERT")
        key = os.environ.get("SSL_KEY")
        if cert and key:
            ssl_ctx = (cert, key)
        else:
            ssl_ctx = "adhoc"
        app.run(debug=True, port=5000, host="0.0.0.0", ssl_context=ssl_ctx)
    else:
        app.run(debug=True, port=5000, host="0.0.0.0")

