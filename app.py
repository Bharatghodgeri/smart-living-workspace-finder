
import os
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

import razorpay
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import get_db_connection


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

razorpay_client = None

if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    razorpay_client = razorpay.Client(
        auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
    )


# ---------------- HELPERS ----------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def save_image(image):
    if not image or not image.filename:
        return None

    if not allowed_file(image.filename):
        return None

    filename = secure_filename(image.filename)

    unique_name = (
        datetime.now().strftime("%Y%m%d%H%M%S%f")
        + "_" + filename
    )

    image.save(os.path.join(UPLOAD_FOLDER, unique_name))
    return "uploads/" + unique_name


def valid_dates(start_date, end_date=None):
    try:
        start = date.fromisoformat(start_date)

        if start < date.today():
            return False

        if end_date:
            end = date.fromisoformat(end_date)
            if end < start:
                return False

        return True

    except (TypeError, ValueError):
        return False


def money(value):
    try:
        amount = Decimal(str(value))

        if not amount.is_finite() or amount <= 0:
            return None

        return amount.quantize(Decimal("0.01"))

    except (TypeError, ValueError, InvalidOperation):
        return None


def is_owner():
    return (
        "user_id" in session
        and session.get("role") == "owner"
    )


def is_user():
    return (
        "user_id" in session
        and session.get("role") == "user"
    )


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- EXPLORE ----------------

@app.route("/explore")
def explore():
    location = request.args.get("location", "").strip()
    listing_type = request.args.get("listing_type", "").strip()
    property_type = request.args.get("property_type", "").strip()
    max_price = request.args.get("max_price", "").strip()

    query = "SELECT * FROM listings WHERE availability = 1"
    params = []

    if location:
        query += " AND location LIKE %s"
        params.append("%" + location + "%")

    if listing_type in ("accommodation", "workspace"):
        query += " AND listing_type = %s"
        params.append(listing_type)

    if property_type:
        query += " AND property_type = %s"
        params.append(property_type)

    if max_price:
        try:
            price = Decimal(max_price)

            if price.is_finite() and price >= 0:
                query += " AND price <= %s"
                params.append(price)

        except InvalidOperation:
            pass

    query += " ORDER BY listing_id DESC"

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(query, tuple(params))
        listings = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "explore.html",
        listings=listings,
        location=location,
        listing_type=listing_type,
        property_type=property_type,
        max_price=max_price
    )


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "")

        if not full_name or not email or not password:
            flash("Please fill all required fields.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        if role not in ("user", "owner"):
            flash("Select a valid role.", "error")
            return redirect(url_for("register"))

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT user_id FROM users WHERE email = %s",
                (email,)
            )

            if cursor.fetchone():
                flash("Email already registered.", "error")
                return redirect(url_for("register"))

            cursor.execute(
                """
                INSERT INTO users
                (full_name, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    full_name,
                    email,
                    generate_password_hash(password),
                    role
                )
            )

            connection.commit()

        finally:
            cursor.close()
            connection.close()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        if is_owner():
            return redirect(url_for("owner_dashboard"))

        if is_user():
            return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )

            user = cursor.fetchone()

        finally:
            cursor.close()
            connection.close()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["user_id"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]

            if user["role"] == "owner":
                return redirect(url_for("owner_dashboard"))

            if user["role"] == "user":
                return redirect(url_for("dashboard"))

            return redirect(url_for("home"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------- USER DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():
    if not is_user():
        return redirect(url_for("login"))

    return render_template("user_dashboard.html")


# ---------------- OWNER DASHBOARD ----------------

@app.route("/owner/dashboard")
def owner_dashboard():
    if not is_owner():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        # Owner listings with review counts and average ratings
        cursor.execute(
            """
            SELECT
                l.*,
                COALESCE(rs.review_count, 0) AS review_count,
                COALESCE(rs.average_rating, 0) AS average_rating
            FROM listings l
            LEFT JOIN (
                SELECT
                    listing_id,
                    COUNT(*) AS review_count,
                    ROUND(AVG(rating), 1) AS average_rating
                FROM reviews
                GROUP BY listing_id
            ) rs ON rs.listing_id = l.listing_id
            WHERE l.owner_id = %s
            ORDER BY l.listing_id DESC
            """,
            (session["user_id"],)
        )

        listings = cursor.fetchall()

        total_listings = len(listings)

        available_listings = sum(
            1 for item in listings if item["availability"]
        )

        # Pending zero-payment booking requests
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM bookings b
            JOIN listings l ON b.listing_id = l.listing_id
            WHERE l.owner_id = %s
              AND b.status = 'pending'
              AND b.booking_type = 'request'
              AND b.payment_status = 'not_paid'
            """,
            (session["user_id"],)
        )

        booking_request_count = cursor.fetchone()["total"]

        # All customer reviews for owner's properties
        cursor.execute(
            """
            SELECT
                r.review_id,
                r.listing_id,
                r.rating,
                r.comment,
                r.created_at,
                u.full_name AS customer_name,
                l.title AS property_title
            FROM reviews r
            JOIN listings l ON r.listing_id = l.listing_id
            JOIN users u ON r.user_id = u.user_id
            WHERE l.owner_id = %s
            ORDER BY r.created_at DESC, r.review_id DESC
            """,
            (session["user_id"],)
        )

        owner_reviews = cursor.fetchall()
        reviews_received = len(owner_reviews)

        # Overall average rating
        cursor.execute(
            """
            SELECT ROUND(AVG(r.rating), 1) AS average_rating
            FROM reviews r
            JOIN listings l ON r.listing_id = l.listing_id
            WHERE l.owner_id = %s
            """,
            (session["user_id"],)
        )

        rating_result = cursor.fetchone()
        owner_average_rating = rating_result["average_rating"] or 0

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "owner_dashboard.html",
        listings=listings,
        total_listings=total_listings,
        available_listings=available_listings,
        booking_request_count=booking_request_count,
        owner_reviews=owner_reviews,
        reviews_received=reviews_received,
        owner_average_rating=owner_average_rating
    )


# ---------------- ADD LISTING ----------------

@app.route("/owner/add-listing", methods=["GET", "POST"])
def add_listing():
    if not is_owner():
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        listing_type = request.form.get("listing_type", "")
        property_type = request.form.get("property_type", "")
        description = request.form.get("description", "")
        location = request.form.get("location", "").strip()
        map_link = request.form.get("map_link", "").strip()
        price = money(request.form.get("price"))
        price_period = request.form.get("price_period", "")
        facilities = request.form.get("facilities", "")
        availability = 1 if "availability" in request.form else 0

        if not title or not location or price is None:
            flash("Enter valid property details.", "error")
            return redirect(url_for("add_listing"))

        if listing_type not in ("accommodation", "workspace"):
            flash("Invalid listing category.", "error")
            return redirect(url_for("add_listing"))

        if price_period not in ("hour", "day", "month"):
            flash("Invalid price period.", "error")
            return redirect(url_for("add_listing"))

        image = request.files.get("image")

        if image and image.filename and not allowed_file(image.filename):
            flash("Invalid image format.", "error")
            return redirect(url_for("add_listing"))

        image_path = save_image(image)

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO listings
                (
                    owner_id, title, listing_type, property_type,
                    description, location, map_link, price,
                    price_period, facilities, image_path, availability
                )
                VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    session["user_id"],
                    title,
                    listing_type,
                    property_type,
                    description,
                    location,
                    map_link,
                    price,
                    price_period,
                    facilities,
                    image_path,
                    availability
                )
            )

            connection.commit()

        finally:
            cursor.close()
            connection.close()

        flash("Property added successfully!", "success")
        return redirect(url_for("owner_dashboard"))

    return render_template("add_listing.html")


# ---------------- EDIT LISTING ----------------

@app.route(
    "/owner/edit-listing/<int:listing_id>",
    methods=["GET", "POST"]
)
def edit_listing(listing_id):
    if not is_owner():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT *
            FROM listings
            WHERE listing_id = %s AND owner_id = %s
            """,
            (listing_id, session["user_id"])
        )

        listing = cursor.fetchone()

        if not listing:
            return "Listing not found!", 404

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            listing_type = request.form.get("listing_type", "")
            property_type = request.form.get("property_type", "")
            description = request.form.get("description", "")
            location = request.form.get("location", "").strip()
            map_link = request.form.get("map_link", "").strip()
            price = money(request.form.get("price"))
            price_period = request.form.get("price_period", "")
            facilities = request.form.get("facilities", "")
            availability = 1 if "availability" in request.form else 0

            if not title or not location or price is None:
                flash("Enter valid property details.", "error")
                return redirect(
                    url_for("edit_listing", listing_id=listing_id)
                )

            if listing_type not in ("accommodation", "workspace"):
                flash("Invalid listing category.", "error")
                return redirect(
                    url_for("edit_listing", listing_id=listing_id)
                )

            if price_period not in ("hour", "day", "month"):
                flash("Invalid price period.", "error")
                return redirect(
                    url_for("edit_listing", listing_id=listing_id)
                )

            image_path = listing["image_path"]
            image = request.files.get("image")

            if image and image.filename:
                if not allowed_file(image.filename):
                    flash("Invalid image format.", "error")
                    return redirect(
                        url_for("edit_listing", listing_id=listing_id)
                    )

                image_path = save_image(image)

            cursor.execute(
                """
                UPDATE listings
                SET title = %s,
                    listing_type = %s,
                    property_type = %s,
                    description = %s,
                    location = %s,
                    map_link = %s,
                    price = %s,
                    price_period = %s,
                    facilities = %s,
                    image_path = %s,
                    availability = %s
                WHERE listing_id = %s AND owner_id = %s
                """,
                (
                    title,
                    listing_type,
                    property_type,
                    description,
                    location,
                    map_link,
                    price,
                    price_period,
                    facilities,
                    image_path,
                    availability,
                    listing_id,
                    session["user_id"]
                )
            )

            connection.commit()
            flash("Property updated successfully!", "success")
            return redirect(url_for("owner_dashboard"))

    finally:
        cursor.close()
        connection.close()

    return render_template("edit_listing.html", listing=listing)


# ---------------- DELETE LISTING ----------------

@app.route(
    "/owner/delete-listing/<int:listing_id>",
    methods=["POST"]
)
def delete_listing(listing_id):
    if not is_owner():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT listing_id
            FROM listings
            WHERE listing_id = %s AND owner_id = %s
            """,
            (listing_id, session["user_id"])
        )

        if not cursor.fetchone():
            flash("Property not found.", "error")
            return redirect(url_for("owner_dashboard"))

        cursor.execute(
            "SELECT COUNT(*) AS total FROM bookings WHERE listing_id = %s",
            (listing_id,)
        )

        bookings_count = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) AS total FROM reviews WHERE listing_id = %s",
            (listing_id,)
        )

        reviews_count = cursor.fetchone()["total"]

        if bookings_count or reviews_count:
            flash(
                "This property has booking or review records "
                "and cannot be deleted.",
                "error"
            )
            return redirect(url_for("owner_dashboard"))

        cursor.execute(
            """
            DELETE FROM listings
            WHERE listing_id = %s AND owner_id = %s
            """,
            (listing_id, session["user_id"])
        )

        connection.commit()

    finally:
        cursor.close()
        connection.close()

    flash("Property deleted successfully!", "success")
    return redirect(url_for("owner_dashboard"))


# ---------------- LISTING DETAILS ----------------

@app.route("/listing/<int:listing_id>")
def listing_details(listing_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT l.*, u.full_name AS owner_name
            FROM listings l
            JOIN users u ON l.owner_id = u.user_id
            WHERE l.listing_id = %s
            """,
            (listing_id,)
        )

        listing = cursor.fetchone()

        if not listing:
            return "Listing not found!", 404

        cursor.execute(
            """
            SELECT r.*, u.full_name
            FROM reviews r
            JOIN users u ON r.user_id = u.user_id
            WHERE r.listing_id = %s
            ORDER BY r.created_at DESC
            """,
            (listing_id,)
        )

        reviews = cursor.fetchall()

        cursor.execute(
            """
            SELECT COUNT(*) AS review_count,
                   ROUND(AVG(rating), 1) AS average_rating
            FROM reviews
            WHERE listing_id = %s
            """,
            (listing_id,)
        )

        rating_data = cursor.fetchone()
        review_count = rating_data["review_count"]
        average_rating = rating_data["average_rating"] or 0

        user_review = None
        can_review = False

        if is_user():
            cursor.execute(
                """
                SELECT *
                FROM reviews
                WHERE user_id = %s AND listing_id = %s
                """,
                (session["user_id"], listing_id)
            )

            user_review = cursor.fetchone()

            if not user_review:
                cursor.execute(
                    """
                    SELECT booking_id
                    FROM bookings
                    WHERE user_id = %s
                      AND listing_id = %s
                      AND status IN ('confirmed', 'completed')
                    LIMIT 1
                    """,
                    (session["user_id"], listing_id)
                )

                can_review = cursor.fetchone() is not None

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "listing_details.html",
        listing=listing,
        reviews=reviews,
        review_count=review_count,
        average_rating=average_rating,
        user_review=user_review,
        can_review=can_review
    )


# ---------------- SUBMIT REVIEW ----------------

@app.route(
    "/listing/<int:listing_id>/review",
    methods=["POST"]
)
def add_review(listing_id):
    if not is_user():
        flash("Login as a user to submit a review.", "error")
        return redirect(url_for("login"))

    try:
        rating = int(request.form.get("rating", "0"))
    except (ValueError, TypeError):
        rating = 0

    comment = request.form.get("comment", "").strip()

    if not 1 <= rating <= 5:
        flash("Select a rating between 1 and 5.", "error")
        return redirect(
            url_for("listing_details", listing_id=listing_id)
        )

    if len(comment) > 1000:
        flash("Review must be within 1000 characters.", "error")
        return redirect(
            url_for("listing_details", listing_id=listing_id)
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT booking_id
            FROM bookings
            WHERE user_id = %s
              AND listing_id = %s
              AND status IN ('confirmed', 'completed')
            LIMIT 1
            """,
            (session["user_id"], listing_id)
        )

        if not cursor.fetchone():
            flash(
                "Only users with confirmed or completed "
                "bookings can submit reviews.",
                "error"
            )
            return redirect(
                url_for("listing_details", listing_id=listing_id)
            )

        cursor.execute(
            """
            SELECT review_id
            FROM reviews
            WHERE user_id = %s AND listing_id = %s
            """,
            (session["user_id"], listing_id)
        )

        if cursor.fetchone():
            flash("You have already reviewed this property.", "error")
            return redirect(
                url_for("listing_details", listing_id=listing_id)
            )

        cursor.execute(
            """
            INSERT INTO reviews
            (user_id, listing_id, rating, comment)
            VALUES (%s, %s, %s, %s)
            """,
            (session["user_id"], listing_id, rating, comment)
        )

        connection.commit()
        flash("Review submitted successfully!", "success")

    except Exception as error:
        connection.rollback()
        print("REVIEW ERROR:", error)
        flash("Unable to submit review.", "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(
        url_for("listing_details", listing_id=listing_id)
    )


# ---------------- ZERO-PAYMENT BOOKING ----------------

@app.route("/book/<int:listing_id>", methods=["POST"])
def book_listing(listing_id):
    if not is_user():
        return redirect(url_for("login"))

    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")

    if not valid_dates(start_date, end_date):
        flash("Select valid booking dates.", "error")
        return redirect(
            url_for("listing_details", listing_id=listing_id)
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT listing_id, price, availability
            FROM listings
            WHERE listing_id = %s
            FOR UPDATE
            """,
            (listing_id,)
        )

        listing = cursor.fetchone()

        if not listing or not listing["availability"]:
            connection.rollback()
            flash("Property is unavailable.", "error")
            return redirect(
                url_for("listing_details", listing_id=listing_id)
            )

        cursor.execute(
            """
            INSERT INTO bookings
            (
                user_id, listing_id, start_date, end_date,
                status, booking_type, total_amount,
                paid_amount, payment_status
            )
            VALUES
            (%s, %s, %s, %s, 'pending', 'request', %s, 0, 'not_paid')
            """,
            (
                session["user_id"],
                listing_id,
                start_date,
                end_date or None,
                listing["price"]
            )
        )

        connection.commit()

        flash(
            "Booking request sent! Waiting for owner approval.",
            "success"
        )

    except Exception as error:
        connection.rollback()
        print("BOOKING ERROR:", error)
        flash("Unable to submit booking request.", "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(
        url_for("listing_details", listing_id=listing_id)
    )


# ---------------- CREATE RAZORPAY ORDER ----------------

@app.route(
    "/create-payment-order/<int:listing_id>",
    methods=["POST"]
)
def create_payment_order(listing_id):
    if not is_user():
        return jsonify(
            success=False,
            message="Please login as a user."
        ), 401

    if not razorpay_client:
        return jsonify(
            success=False,
            message="Razorpay is not configured."
        ), 503

    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")
    payment_type = request.form.get("payment_type")
    amount = request.form.get("amount")

    if not valid_dates(start_date, end_date):
        return jsonify(
            success=False,
            message="Select valid booking dates."
        ), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT *
            FROM listings
            WHERE listing_id = %s
            """,
            (listing_id,)
        )

        listing = cursor.fetchone()

        if not listing:
            return jsonify(
                success=False,
                message="Property not found."
            ), 404

        if not listing["availability"]:
            return jsonify(
                success=False,
                message="Property is unavailable."
            ), 409

        total_price = Decimal(str(listing["price"]))

        minimum_advance = (
            total_price * Decimal("0.20")
        ).quantize(Decimal("0.01"))

        if payment_type == "full":
            payment_amount = total_price

        elif payment_type == "advance":
            payment_amount = money(amount)

            if payment_amount is None:
                return jsonify(
                    success=False,
                    message="Invalid advance amount."
                ), 400

            if (
                payment_amount < minimum_advance
                or payment_amount >= total_price
            ):
                return jsonify(
                    success=False,
                    message=(
                        "Advance must be at least 20% "
                        "and less than the full amount."
                    )
                ), 400

        else:
            return jsonify(
                success=False,
                message="Invalid payment option."
            ), 400

        amount_paise = int(payment_amount * 100)

        order = razorpay_client.order.create(
            {
                "amount": amount_paise,
                "currency": "INR",
                "receipt": (
                    "SL"
                    + str(listing_id)
                    + "_"
                    + datetime.now().strftime("%Y%m%d%H%M%S%f")
                )[:40]
            }
        )

        cursor.execute(
            """
            INSERT INTO bookings
            (
                user_id, listing_id, start_date, end_date,
                status, booking_type, total_amount,
                paid_amount, payment_status, razorpay_order_id
            )
            VALUES
            (%s, %s, %s, %s, 'pending', 'paid',
             %s, 0, 'pending', %s)
            """,
            (
                session["user_id"],
                listing_id,
                start_date,
                end_date or None,
                total_price,
                order["id"]
            )
        )

        booking_id = cursor.lastrowid
        connection.commit()

        return jsonify(
            success=True,
            booking_id=booking_id,
            order_id=order["id"],
            amount=order["amount"],
            currency=order["currency"],
            key_id=RAZORPAY_KEY_ID,
            property_title=listing["title"],
            payment_amount=float(payment_amount)
        )

    except Exception as error:
        connection.rollback()
        print("CREATE PAYMENT ERROR:", error)

        return jsonify(
            success=False,
            message="Unable to create payment order."
        ), 500

    finally:
        cursor.close()
        connection.close()


# ---------------- VERIFY PAYMENT ----------------

@app.route("/verify-payment", methods=["POST"])
def verify_payment():
    if not is_user():
        return jsonify(
            success=False,
            message="Login required."
        ), 401

    if not razorpay_client:
        return jsonify(
            success=False,
            message="Payment service unavailable."
        ), 503

    data = request.get_json(silent=True) or {}

    booking_id = data.get("booking_id")
    order_id = data.get("razorpay_order_id")
    payment_id = data.get("razorpay_payment_id")
    signature = data.get("razorpay_signature")

    if not all((booking_id, order_id, payment_id, signature)):
        return jsonify(
            success=False,
            message="Missing payment details."
        ), 400

    try:
        razorpay_client.utility.verify_payment_signature(
            {
                "razorpay_order_id": order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature": signature
            }
        )

    except Exception:
        return jsonify(
            success=False,
            message="Invalid payment signature."
        ), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT *
            FROM bookings
            WHERE booking_id = %s
              AND user_id = %s
            FOR UPDATE
            """,
            (booking_id, session["user_id"])
        )

        booking = cursor.fetchone()

        if not booking:
            connection.rollback()

            return jsonify(
                success=False,
                message="Booking not found."
            ), 404

        if booking["razorpay_order_id"] != order_id:
            connection.rollback()

            return jsonify(
                success=False,
                message="Payment order mismatch."
            ), 400

        if (
            booking["status"] == "confirmed"
            and booking["payment_status"] == "paid"
        ):
            connection.commit()

            return jsonify(
                success=True,
                message="Booking already confirmed.",
                booking_id=booking_id
            )

        if (
            booking["status"] != "pending"
            or booking["booking_type"] != "paid"
            or booking["payment_status"] != "pending"
        ):
            connection.rollback()

            return jsonify(
                success=False,
                message="Booking cannot be confirmed."
            ), 409

        cursor.execute(
            """
            SELECT *
            FROM listings
            WHERE listing_id = %s
            FOR UPDATE
            """,
            (booking["listing_id"],)
        )

        listing = cursor.fetchone()

        if not listing or not listing["availability"]:
            connection.rollback()

            return jsonify(
                success=False,
                message=(
                    "Property is no longer available. "
                    "Contact support if payment was captured."
                )
            ), 409

        payment = razorpay_client.payment.fetch(payment_id)
        order = razorpay_client.order.fetch(order_id)

        if (
            payment.get("order_id") != order_id
            or payment.get("status") != "captured"
            or order.get("currency") != "INR"
            or payment.get("currency") != "INR"
            or int(payment["amount"]) != int(order["amount"])
        ):
            connection.rollback()

            return jsonify(
                success=False,
                message="Payment verification failed."
            ), 400

        paid_amount = (
            Decimal(str(payment["amount"])) / Decimal("100")
        ).quantize(Decimal("0.01"))

        total_price = Decimal(str(booking["total_amount"]))

        minimum_advance = (
            total_price * Decimal("0.20")
        ).quantize(Decimal("0.01"))

        if (
            paid_amount < minimum_advance
            or paid_amount > total_price
        ):
            connection.rollback()

            return jsonify(
                success=False,
                message="Invalid payment amount."
            ), 400

        # Automatically confirm paid bookings
        cursor.execute(
            """
            UPDATE bookings
            SET status = 'confirmed',
                booking_type = 'paid',
                paid_amount = %s,
                payment_status = 'paid',
                razorpay_payment_id = %s,
                razorpay_signature = %s
            WHERE booking_id = %s
            """,
            (
                paid_amount,
                payment_id,
                signature,
                booking_id
            )
        )

        # Mark property unavailable
        cursor.execute(
            """
            UPDATE listings
            SET availability = 0
            WHERE listing_id = %s
            """,
            (booking["listing_id"],)
        )

        # Cancel other pending zero-payment requests
        cursor.execute(
            """
            UPDATE bookings
            SET status = 'cancelled'
            WHERE listing_id = %s
              AND booking_id != %s
              AND status = 'pending'
              AND booking_type = 'request'
              AND payment_status = 'not_paid'
            """,
            (booking["listing_id"], booking_id)
        )

        connection.commit()

        return jsonify(
            success=True,
            message="Payment successful! Booking confirmed.",
            booking_id=booking_id,
            paid_amount=float(paid_amount)
        )

    except Exception as error:
        connection.rollback()
        print("VERIFY PAYMENT ERROR:", error)

        return jsonify(
            success=False,
            message=(
                "Payment verification could not be completed. "
                "Check My Bookings before paying again."
            )
        ), 500

    finally:
        cursor.close()
        connection.close()


# ---------------- OWNER BOOKING REQUESTS ----------------

@app.route("/owner/booking-requests")
def owner_booking_requests():
    if not is_owner():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                b.*,
                l.title,
                l.location,
                l.image_path,
                l.property_type,
                l.price,
                l.price_period,
                u.full_name AS user_name,
                u.email AS user_email
            FROM bookings b
            JOIN listings l ON b.listing_id = l.listing_id
            JOIN users u ON b.user_id = u.user_id
            WHERE l.owner_id = %s
            ORDER BY b.booking_id DESC
            """,
            (session["user_id"],)
        )

        booking_requests = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "owner_booking_requests.html",
        booking_requests=booking_requests
    )


# ---------------- ACCEPT ZERO-PAYMENT BOOKING ----------------

@app.route(
    "/owner/accept-booking/<int:booking_id>",
    methods=["POST"]
)
def accept_booking(booking_id):
    if not is_owner():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT b.*
            FROM bookings b
            JOIN listings l ON b.listing_id = l.listing_id
            WHERE b.booking_id = %s
              AND l.owner_id = %s
            FOR UPDATE
            """,
            (booking_id, session["user_id"])
        )

        booking = cursor.fetchone()

        if not booking:
            flash("Booking request not found.", "error")
            return redirect(url_for("owner_booking_requests"))

        if not (
            booking["status"] == "pending"
            and booking["booking_type"] == "request"
            and booking["payment_status"] == "not_paid"
        ):
            flash(
                "Only pending ₹0 booking requests can be accepted.",
                "error"
            )
            return redirect(url_for("owner_booking_requests"))

        cursor.execute(
            """
            SELECT availability
            FROM listings
            WHERE listing_id = %s
            FOR UPDATE
            """,
            (booking["listing_id"],)
        )

        listing = cursor.fetchone()

        if not listing or not listing["availability"]:
            connection.rollback()
            flash("Property is already unavailable.", "error")
            return redirect(url_for("owner_booking_requests"))

        cursor.execute(
            """
            UPDATE bookings
            SET status = 'confirmed'
            WHERE booking_id = %s
            """,
            (booking_id,)
        )

        cursor.execute(
            """
            UPDATE listings
            SET availability = 0
            WHERE listing_id = %s
            """,
            (booking["listing_id"],)
        )

        cursor.execute(
            """
            UPDATE bookings
            SET status = 'cancelled'
            WHERE listing_id = %s
              AND booking_id != %s
              AND status = 'pending'
              AND booking_type = 'request'
              AND payment_status = 'not_paid'
            """,
            (booking["listing_id"], booking_id)
        )

        connection.commit()
        flash("Booking accepted successfully!", "success")

    except Exception as error:
        connection.rollback()
        print("ACCEPT BOOKING ERROR:", error)
        flash("Unable to accept booking.", "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("owner_booking_requests"))


# ---------------- REJECT ZERO-PAYMENT BOOKING ----------------

@app.route(
    "/owner/reject-booking/<int:booking_id>",
    methods=["POST"]
)
def reject_booking(booking_id):
    if not is_owner():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT b.*
            FROM bookings b
            JOIN listings l ON b.listing_id = l.listing_id
            WHERE b.booking_id = %s
              AND l.owner_id = %s
            FOR UPDATE
            """,
            (booking_id, session["user_id"])
        )

        booking = cursor.fetchone()

        if not booking:
            flash("Booking request not found.", "error")
            return redirect(url_for("owner_booking_requests"))

        if not (
            booking["status"] == "pending"
            and booking["booking_type"] == "request"
            and booking["payment_status"] == "not_paid"
        ):
            flash(
                "Only pending ₹0 booking requests can be rejected.",
                "error"
            )
            return redirect(url_for("owner_booking_requests"))

        cursor.execute(
            """
            UPDATE bookings
            SET status = 'cancelled'
            WHERE booking_id = %s
            """,
            (booking_id,)
        )

        connection.commit()
        flash("Booking rejected successfully.", "success")

    except Exception as error:
        connection.rollback()
        print("REJECT BOOKING ERROR:", error)
        flash("Unable to reject booking.", "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("owner_booking_requests"))


# ---------------- MY BOOKINGS ----------------

@app.route("/my-bookings")
def my_bookings():
    if not is_user():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                b.*,
                l.title,
                l.location,
                l.image_path,
                l.property_type,
                l.price,
                l.price_period
            FROM bookings b
            JOIN listings l ON b.listing_id = l.listing_id
            WHERE b.user_id = %s
            ORDER BY b.booking_id DESC
            """,
            (session["user_id"],)
        )

        bookings = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "my_bookings.html",
        bookings=bookings
    )


# ---------------- CANCEL BOOKING ----------------

@app.route(
    "/cancel-booking/<int:booking_id>",
    methods=["POST"]
)
def cancel_booking(booking_id):
    if not is_user():
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT *
            FROM bookings
            WHERE booking_id = %s AND user_id = %s
            FOR UPDATE
            """,
            (booking_id, session["user_id"])
        )

        booking = cursor.fetchone()

        if not booking:
            flash("Booking not found.", "error")
            return redirect(url_for("my_bookings"))

        if booking["status"] in ("cancelled", "completed"):
            flash("This booking cannot be cancelled.", "error")
            return redirect(url_for("my_bookings"))

        was_confirmed = booking["status"] == "confirmed"

        cursor.execute(
            """
            UPDATE bookings
            SET status = 'cancelled'
            WHERE booking_id = %s
            """,
            (booking_id,)
        )

        if was_confirmed:
            cursor.execute(
                """
                UPDATE listings
                SET availability = 1
                WHERE listing_id = %s
                """,
                (booking["listing_id"],)
            )

        connection.commit()

        if booking["payment_status"] == "paid":
            flash(
                "Booking cancelled. Any refund must be "
                "processed separately.",
                "success"
            )
        else:
            flash("Booking cancelled successfully.", "success")

    except Exception as error:
        connection.rollback()
        print("CANCEL BOOKING ERROR:", error)
        flash("Unable to cancel booking.", "error")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("my_bookings"))


# ---------------- RUN APP ----------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False
    )
