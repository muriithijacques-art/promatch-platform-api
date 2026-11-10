import os
import hmac
from datetime import datetime, timezone, date

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt


app = Flask(__name__)
CORS(app)

database_url = os.getenv("DATABASE_URL", "sqlite:///promatch.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# DATABASE MODEL
class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    league = db.Column(db.String(120), nullable=False)
    home_team = db.Column(db.String(120), nullable=False)
    away_team = db.Column(db.String(120), nullable=False)
    kickoff_at = db.Column(db.DateTime, nullable=False)
    prediction = db.Column(db.String(250), nullable=False)
    analysis = db.Column(db.Text, default="")
    is_free_pick = db.Column(db.Boolean, default=False)
    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


# TOKEN HELPERS
def create_token(role):
    secret = os.getenv("JWT_SECRET")

    if not secret:
        raise RuntimeError("JWT_SECRET is not configured")

    return jwt.encode(
        {
            "role": role,
            "exp": datetime.now(timezone.utc).timestamp() + 86400
        },
        secret,
        algorithm="HS256"
    )


def verify_token(token):
    secret = os.getenv("JWT_SECRET")

    if not secret:
        return None

    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


def admin_required():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return None

    data = verify_token(header.split(" ", 1)[1])

    if not data or data.get("role") != "admin":
        return None

    return data


# HEALTH CHECK
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "ProMatch Predictor API"
    })


# ADMIN LOGIN
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "")
    password = data.get("password", "")

    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        return jsonify({
            "error": "Admin login is not configured"
        }), 503

    valid = (
    hmac.compare_digest(
        str(email).strip().lower(),
        admin_email.strip().lower()
    )
    and hmac.compare_digest(
        str(password),
        admin_password
    )
)

    if not valid:
        return jsonify({"error": "Invalid login"}), 401

    return jsonify({
        "token": create_token("admin"),
        "message": "Admin login successful"
    })

# PUBLISH A MATCH
@app.route("/api/admin/matches", methods=["POST"])
def add_match():
    if not admin_required():
        return jsonify({"error": "Admin access required"}), 401

    data = request.get_json(silent=True) or {}

    required = [
        "league",
        "home_team",
        "away_team",
        "kickoff_at",
        "prediction"
    ]

    if any(not data.get(field) for field in required):
        return jsonify({
            "error": "Please provide all required match details"
        }), 400

    try:
        kickoff = datetime.fromisoformat(
            data["kickoff_at"].replace("Z", "+00:00")
        )

        if kickoff.tzinfo is None:
            return jsonify({
                "error": "Kickoff time must include a timezone"
            }), 400

        is_free = bool(data.get("is_free_pick", False))

        if is_free:
            free_date = kickoff.date()

            existing_free = Match.query.filter(
                Match.is_free_pick.is_(True),
                Match.published.is_(True),
                db.func.date(Match.kickoff_at) == free_date
            ).count()

            if existing_free >= 3:
                return jsonify({
                    "error": "Only 3 free matches are allowed per day."
                }), 400

        match = Match(
            league=data["league"],
            home_team=data["home_team"],
            away_team=data["away_team"],
            kickoff_at=kickoff.astimezone(timezone.utc),
            prediction=data["prediction"],
            analysis=data.get("analysis", ""),
            is_free_pick=is_free,
            published=bool(data.get("published", True))
        )

        db.session.add(match)
        db.session.commit()

        return jsonify({
            "message": "Match published successfully",
            "match_id": match.id
        }), 201

    except ValueError:
        return jsonify({"error": "Invalid kickoff date or time"}), 400

# ADMIN VIEW ALL MATCHES
@app.route("/api/admin/matches", methods=["GET"])
def admin_get_matches():
    if not admin_required():
        return jsonify({"error": "Admin access required"}), 401

    matches = Match.query.order_by(
        Match.kickoff_at.desc()
    ).all()

    result = []

    for match in matches:
        result.append({
            "id": match.id,
            "league": match.league,
            "home_team": match.home_team,
            "away_team": match.away_team,
            "kickoff_at": match.kickoff_at.isoformat(),
            "prediction": match.prediction,
            "analysis": match.analysis,
            "is_free_pick": match.is_free_pick,
            "published": match.published
        })

    return jsonify({"matches": result})

# ADMIN EDIT MATCH
@app.route("/api/admin/matches/<int:match_id>", methods=["PUT"])
def edit_match(match_id):
    if not admin_required():
        return jsonify({"error": "Admin access required"}), 401

    match = db.session.get(Match, match_id)

    if not match:
        return jsonify({"error": "Match not found"}), 404

    data = request.get_json(silent=True) or {}

    try:
        for field in ["league", "home_team", "away_team", "prediction", "analysis"]:
            if field in data:
                setattr(match, field, data[field])

        if "kickoff_at" in data:
            kickoff = datetime.fromisoformat(
                data["kickoff_at"].replace("Z", "+00:00")
            )
            if kickoff.tzinfo is None:
                return jsonify({"error": "Timezone required"}), 400
            match.kickoff_at = kickoff.astimezone(timezone.utc)

        if "is_free_pick" in data:
            match.is_free_pick = bool(data["is_free_pick"])

        if "published" in data:
            match.published = bool(data["published"])

        db.session.commit()

        return jsonify({"message": "Match updated successfully"})

    except ValueError:
        return jsonify({"error": "Invalid date or time"}), 400


# ADMIN DELETE MATCH
@app.route("/api/admin/matches/<int:match_id>", methods=["DELETE"])
def delete_match(match_id):
    if not admin_required():
        return jsonify({"error": "Admin access required"}), 401

    match = db.session.get(Match, match_id)

    if not match:
        return jsonify({"error": "Match not found"}), 404

    db.session.delete(match)
    db.session.commit()

    return jsonify({"message": "Match deleted successfully"})
# VIEW MATCHES
@app.route("/api/matches", methods=["GET"])
def get_matches():
    matches = Match.query.filter_by(
        published=True
    ).order_by(Match.kickoff_at.asc()).all()

    # Initial version: public users see up to three
    # matches selected by the administrator.
    free_matches = [
        match for match in matches if match.is_free_pick
    ][:3]

    result = []

    for match in free_matches:
        result.append({
            "id": match.id,
            "league": match.league,
            "home_team": match.home_team,
            "away_team": match.away_team,
            "kickoff_at": match.kickoff_at.isoformat(),
            "prediction": match.prediction
        })

    return jsonify({
        "matches": result,
        "access": "free",
        "message": "VIP members will receive access to all published matches."
    })


# CREATE DATABASE TABLES
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
