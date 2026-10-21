from flask import Flask, render_template, request,session,redirect,url_for,jsonify
from sqlalchemy import Table, Column, Integer, String, MetaData,Float, Date, Text, JSON
from sqlalchemy.exc import ProgrammingError, IntegrityError
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import create_engine
from flask_sqlalchemy import SQLAlchemy
from flask import flash
from datetime import datetime
import logging
from flask_mail import Mail
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash,check_password_hash
import json
from functools import wraps
import re
import os
import math
from sqlalchemy import select
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, TextAreaField, DateField, IntegerField
from wtforms.validators import DataRequired
from sqlalchemy import or_
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.charset import Charset, BASE64
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, date
import atexit
from google.cloud import translate_v2 as translate
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
import hmac
import threading
import time

# Passwords and keys live in a .env file next to this script (never committed).
# See .env.example for the list of settings.
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


def require_env(name):
    """Read a required setting from the environment, failing fast if it is missing."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing setting {name}. Add it to the .env file (see .env.example).")
    return value


def env_flag(name, default=False):
    """Read a true/false setting from the environment."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


DEBUG = env_flag("FLASK_DEBUG")  # Keep false on the live server

app = Flask(__name__)
app.secret_key = require_env("SECRET_KEY")  # Signs the session cookie
logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO)
app.config['SQLALCHEMY_DATABASE_URI'] = require_env("DATABASE_URL")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # JavaScript cannot read the login cookie
    SESSION_COOKIE_SAMESITE="Lax",    # Other sites cannot send it along with their requests
    SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE"),  # true once the site runs on HTTPS
    WTF_CSRF_TIME_LIMIT=None,         # A CSRF token stays valid for the whole login session
)

# Every POST must carry the CSRF token: forms send it as a hidden field and
# fetch() calls send it as the X-CSRFToken header (see static/js/csrf.js).
csrf = CSRFProtect(app)

# Behind a hosting proxy (Render, Railway, Nginx...) this makes request.remote_addr
# the visitor's real IP, which the login limit below relies on.
if env_flag("TRUST_PROXY"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


def reflect_existing(metadata, *table_names):
    """Load just the named tables that exist into metadata (not every table in the database)."""
    inspector = db.inspect(db.engine)
    existing = [name for name in table_names if inspector.has_table(name)]
    if existing:
        metadata.reflect(bind=db.engine, only=existing, extend_existing=True)

NOTES_MAX_LENGTH = 200  # Maximum characters allowed in an entry's notes
app.jinja_env.globals["NOTES_MAX_LENGTH"] = NOTES_MAX_LENGTH  # Same limit in the templates


class Registration(db.Model):
    __tablename__ = 'Registeration'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    JoinDate = db.Column(db.DateTime, default=datetime.utcnow)
    bName = db.Column(db.String(100), nullable=False)
    bAddress = db.Column(db.String(200), nullable=False)
    bType = db.Column(db.String(20), nullable=True)
    UserID = db.Column(db.String(20), nullable=False)
    Email = db.Column(db.String(50), nullable=False)
    Contact = db.Column(db.String(15), nullable=False)
    Password = db.Column(db.String(255), nullable=False)


class EntryReminder(db.Model):
    """A reminder email scheduled for 12:00 AM on an entry's due date."""
    __tablename__ = 'entry_reminders'
    __table_args__ = (db.UniqueConstraint('user_id', 'customer_name', 'entry_id'),)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(20), nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    entry_id = db.Column(db.Integer, nullable=False)
    recipient = db.Column(db.String(10), nullable=False)  # "customer" or "owner"
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_attempt = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, nullable=True)

@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """A form or request arrived without a valid CSRF token (e.g. the page was open too long)."""
    message = "Your session has expired. Please refresh the page and try again."
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"error": message}), 400
    flash(message, "error")
    return redirect(request.referrer or url_for("index"))


# ---------------------------------------------------------------------------
# Login limit
#
# After LOGIN_MAX_FAILURES wrong passwords for the same user ID from the same IP
# address, that pair is locked for LOGIN_LOCK_SECONDS. Kept in memory, so it
# resets when the server restarts (the app runs as a single process).
# ---------------------------------------------------------------------------
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 15 * 60
_login_failures = {}  # (scope, ip, user id) -> {"count", "first", "locked_until"}
_login_failures_lock = threading.Lock()


def _login_key(scope, user_id):
    return (scope, request.remote_addr or "unknown", user_id.lower())


def login_locked_minutes(scope, user_id):
    """Minutes left before this IP may try this user ID again (0 = not locked)."""
    with _login_failures_lock:
        info = _login_failures.get(_login_key(scope, user_id))
        remaining = info["locked_until"] - time.time() if info else 0
    return math.ceil(remaining / 60) if remaining > 0 else 0


def record_login_failure(scope, user_id):
    now = time.time()
    with _login_failures_lock:
        if len(_login_failures) > 10000:  # Forget stale entries so the dict cannot grow forever
            for key in [k for k, v in _login_failures.items()
                        if now - v["first"] > LOGIN_LOCK_SECONDS and v["locked_until"] < now]:
                del _login_failures[key]
        key = _login_key(scope, user_id)
        info = _login_failures.get(key)
        if not info or now - info["first"] > LOGIN_LOCK_SECONDS:
            info = {"count": 0, "first": now, "locked_until": 0}
        info["count"] += 1
        if info["count"] >= LOGIN_MAX_FAILURES:
            info["locked_until"] = now + LOGIN_LOCK_SECONDS
        _login_failures[key] = info


def clear_login_failures(scope, user_id):
    with _login_failures_lock:
        _login_failures.pop(_login_key(scope, user_id), None)


def too_many_attempts_message(minutes):
    return f"Too many failed attempts. Please try again in {minutes} minute{'s' if minutes != 1 else ''}."


@app.route("/")
def index():

    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Handling login form submission
        user_id = request.form.get("UserID", "").strip()  # Get UserId from form input
        password = request.form.get("Password", "").strip()  # Get Password from form input

        # Check for empty fields
        if not user_id or not password:
            return render_template(
                "login.html",
                error_message="Please fill in all fields.",
                user_id=user_id  # Preserve the entered UserID
            )

        # Longer than registration allows can never be a real account; skip the database
        if (len(user_id) > REGISTRATION_RULES["UserID"]["max"]
                or len(password) > REGISTRATION_RULES["Password"]["max"]):
            return render_template(
                "login.html",
                error_message="Wrong password or username entered. Please try again.",
                user_id=user_id[:REGISTRATION_RULES["UserID"]["max"]]
            )

        locked_minutes = login_locked_minutes("user", user_id)
        if locked_minutes:
            return render_template(
                "login.html",
                error_message=too_many_attempts_message(locked_minutes),
                user_id=user_id
            ), 429

        # Query user from the database
        user = Registration.query.filter_by(UserID=user_id).first()

        # Validate user credentials
        if user and check_password_hash(user.Password, password):
            clear_login_failures("user", user_id)
            session.clear()  # Start a fresh session on login
            session["user_id"] = user.UserID  # Save user info in the session
            session["b_name"] = user.bName
            return redirect(url_for("customer"))

        # Invalid credentials
        record_login_failure("user", user_id)
        return render_template(
            "login.html",
            error_message="Wrong password or username entered. Please try again.",
            user_id=user_id  # Preserve the entered UserID
        )

    # Render login page for GET requests
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# Registration validation
#
# Fields are listed in the order they appear on the form (the first problem
# found is the one shown to the user).
#
# These rules are the single source of truth: the server checks them below,
# and register.html receives them (as JSON) to run the same checks in the
# browser and to set each field's maxlength. Patterns use syntax that works
# in both Python and JavaScript.
# ---------------------------------------------------------------------------
REGISTRATION_RULES = {
    "bName": {
        "label": "Business name", "required": True, "min": 2, "max": 50, "needs_letter": True,
        "pattern": r"^[A-Za-z0-9 &.,'()/-]+$",
        "message": "Business name can only contain letters, numbers, spaces and & . , ' ( ) / -",
    },
    "bType": {
        "label": "Business type", "required": False, "max": 20,
        "pattern": r"^[A-Za-z &/-]+$",
        "message": "Business type can only contain letters, spaces and & / -",
    },
    "bAddress": {
        "label": "Business address", "required": True, "min": 5, "max": 200, "needs_letter": True,
        "pattern": r"^[^<>]+$",
        "message": "Business address cannot contain < or >",
    },
    "UserID": {
        "label": "User ID", "required": True, "min": 4, "max": 20,
        "pattern": r"^[A-Za-z][A-Za-z0-9_]*$",
        "message": "User ID must start with a letter and can only contain letters, numbers and _ (no spaces)",
    },
    "Contact": {
        "label": "Contact number", "required": True, "min": 10, "max": 10,
        "pattern": r"^[6-9][0-9]{9}$",
        "message": "Contact number must be a 10-digit mobile number starting with 6, 7, 8 or 9",
    },
    "Email": {
        "label": "Email", "required": True, "max": 50,
        "pattern": r"^[^\s@]+@[^\s@]+\.[A-Za-z]{2,}$",
        "message": "Please enter a valid email address, e.g. name@example.com",
    },
    "Password": {
        "label": "Password", "required": True, "min": 8, "max": 8,
        "pattern": r"^(?=.*[A-Za-z])(?=.*[0-9])(?=.*[^A-Za-z0-9])\S+$",
        "message": "Password must include at least one letter, one number and one symbol, with no spaces",
    },
}
app.jinja_env.globals["REGISTRATION_RULES"] = REGISTRATION_RULES

# Fields where repeated spaces are collapsed ("Sharma   Traders" -> "Sharma Traders")
SPACE_COLLAPSED_FIELDS = ("bName", "bType", "bAddress")


def clean_registration_form(form):
    """Return the submitted values, trimmed and normalised (passwords untouched)."""
    data = {}
    for field in REGISTRATION_RULES:
        value = form.get(field, "") or ""
        if field != "Password":
            value = value.strip()
            if field in SPACE_COLLAPSED_FIELDS:
                value = " ".join(value.split())
        data[field] = value
    data["Email"] = data["Email"].lower()
    data["ConfirmPassword"] = form.get("ConfirmPassword", "") or ""
    return data


def check_field(field, value):
    """Return an error message for one field, or None if it is valid."""
    rule = REGISTRATION_RULES[field]
    label = rule["label"]
    if not value:
        return f"{label} is required." if rule["required"] else None
    min_len, max_len = rule.get("min"), rule.get("max")
    if min_len and max_len and min_len == max_len and len(value) != min_len:
        return f"{label} must be exactly {min_len} characters."
    if min_len and len(value) < min_len:
        return f"{label} must be at least {min_len} characters."
    if max_len and len(value) > max_len:
        return f"{label} cannot be longer than {max_len} characters."
    if not re.match(rule["pattern"], value):
        return rule["message"] + "."
    if rule.get("needs_letter") and not re.search(r"[A-Za-z]", value):
        return f"{label} must contain at least one letter."
    return None


def validate_registration(data):
    """Return {field: message} for every problem in the submitted data."""
    errors = {}
    for field in REGISTRATION_RULES:
        message = check_field(field, data[field])
        if message:
            errors[field] = message

    if "Password" not in errors and data["Password"] != data["ConfirmPassword"]:
        errors["ConfirmPassword"] = "Passwords do not match."

    # Uniqueness. User IDs are compared ignoring case because each user's
    # customer table is named after the lower-case User ID.
    if "UserID" not in errors and Registration.query.filter(
        db.func.lower(Registration.UserID) == data["UserID"].lower()
    ).first():
        errors["UserID"] = "This User ID is already taken. Please choose a different one."
    if "Email" not in errors and Registration.query.filter(
        db.func.lower(Registration.Email) == data["Email"]
    ).first():
        errors["Email"] = "An account with this email already exists."
    return errors


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = clean_registration_form(request.form)
        errors = validate_registration(data)

        if errors:
            form_data = {k: v for k, v in data.items() if k not in ("Password", "ConfirmPassword")}
            return render_template(
                "register.html",
                alert_message=next(iter(errors.values())),  # first problem, in form order
                field_errors=errors,
                form_data=form_data,
            ), 400

        new_registration = Registration(
            bName=data["bName"],
            bAddress=data["bAddress"],
            bType=data["bType"] or None,
            UserID=data["UserID"],
            Email=data["Email"],
            Contact=data["Contact"],
            Password=generate_password_hash(data["Password"]),
        )
        db.session.add(new_registration)
        db.session.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", field_errors={})


@app.route("/customer", methods=["GET"])
def customer():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    b_name = session.get("b_name", "Default Business Name")
    table_name = f"{user_id.lower()}_customers"  # Convert user_id to lowercase
    metadata = MetaData()
    overall_total_sum = 0  # Initialize total sum
    search_query = request.args.get("search", "").strip().lower()  # Get the search query and make it case-insensitive

    try:
        # Reflect the specific table
        reflect_existing(metadata, table_name)

        if table_name not in metadata.tables:  # New business with no customers yet
            return render_template(
                "customer.html",
                user_id=user_id,
                customers=[],
                overall_total_sum=0,
                b_name=b_name,
            )

        customer_table = metadata.tables[table_name]

        # Open a connection to execute the query
        with db.engine.connect() as connection:
            query = customer_table.select()

            if search_query:
                # Add a filter to the query for the search functionality (% and _ are matched literally)
                query = query.where(
                    db.func.lower(customer_table.c.name).contains(search_query, autoescape=True)
                )

            result = connection.execute(query)

            # Fetch column names and rows
            column_names = result.keys()
            customers = [dict(zip(column_names, row)) for row in result]

        # Calculate overall_total for each customer and the total sum
        reflect_existing(metadata, *(f"{user_id}_{c['name'].lower()}" for c in customers))
        for customer in customers:
            customer_name = customer["name"]
            entries_table_name = f"{user_id}_{customer_name.lower()}"

            if entries_table_name in metadata.tables:
                entries_table = metadata.tables[entries_table_name]
                with db.engine.connect() as connection:
                    total_query = db.func.sum(entries_table.c.Total)
                    overall_total = connection.execute(db.select(total_query)).scalar()
                    customer["overall_total"] = overall_total if overall_total else 0
                    overall_total_sum += customer["overall_total"]  # Add to overall total
            else:
                customer["overall_total"] = 0  # Default to 0 if no entries table exists

    except Exception as e:
        app.logger.error(f"Error while loading customers: {e}")
        customers = []  # Default to empty if an error occurs

    # Pass the filtered results to the template
    return render_template(
        "customer.html",
        user_id=user_id,
        customers=customers,
        overall_total_sum=overall_total_sum,
        b_name=b_name,
    )

# @app.route("/customer")
# def customer():
#     if "user_id" not in session:
#         return redirect(url_for("login"))

#     user_id = session["user_id"]
#     b_name = session.get("b_name", "Default Business Name")
#     table_name = f"{user_id.lower()}_customers"  # Convert user_id to lowercase
#     metadata = MetaData()
#     overall_total_sum = 0  # Initialize total sum

#     try:
#         # Reflect the specific table
#         metadata.reflect(bind=db.engine, only=[table_name])

#         if table_name not in metadata.tables:
#             print(f"Table {table_name} does not exist.")
#             return render_template("customer.html", user_id=user_id, customers=[], overall_total_sum=0)

#         customer_table = metadata.tables[table_name]

#         # Open a connection to execute the query
#         with db.engine.connect() as connection:
#             query = customer_table.select()
#             result = connection.execute(query)

#             # Fetch column names and rows
#             column_names = result.keys()
#             customers = [dict(zip(column_names, row)) for row in result]

#         # Calculate overall_total for each customer and the total sum
#         for customer in customers:
#             customer_name = customer["name"]
#             entries_table_name = f"{user_id}_{customer_name.lower()}"
#             metadata.reflect(bind=db.engine)

#             if entries_table_name in metadata.tables:
#                 entries_table = metadata.tables[entries_table_name]
#                 with db.engine.connect() as connection:
#                     total_query = db.func.sum(entries_table.c.Total)
#                     overall_total = connection.execute(db.select(total_query)).scalar()
#                     customer["overall_total"] = overall_total if overall_total else 0
#                     overall_total_sum += customer["overall_total"]  # Add to overall total
#             else:
#                 customer["overall_total"] = 0  # Default to 0 if no entries table exists

#     except Exception as e:
#         print(f"Error occurred: {e}")
#         customers = []  # Default to empty if an error occurs

#     return render_template("customer.html", user_id=user_id, customers=customers, overall_total_sum=overall_total_sum, b_name=b_name)


# ---------------------------------------------------------------------------
# Customer details
#
# Each customer's entries live in a table named "<user id>_<customer name>".
# PostgreSQL cuts table names at 63 characters, so names are kept short enough
# that two customers can never end up sharing a table, and limited to plain
# characters that are safe in table names and URLs.
# ---------------------------------------------------------------------------
CUSTOMER_NAME_MAX = 40
CUSTOMER_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 .&'\-]*$"
CUSTOMER_EMAIL_MAX = 100
CUSTOMER_CONTACT_PATTERN = r"^[0-9]{10}$"
assert REGISTRATION_RULES["UserID"]["max"] + 1 + CUSTOMER_NAME_MAX <= 63, "Entries table names would be too long"
app.jinja_env.globals.update(
    CUSTOMER_NAME_MAX=CUSTOMER_NAME_MAX,
    CUSTOMER_NAME_PATTERN=CUSTOMER_NAME_PATTERN,
)


def clean_customer_name(name):
    """Trim the name and collapse repeated spaces."""
    return " ".join((name or "").split())


def validate_customer_name(name):
    """Return an error message for an invalid customer name, or None."""
    if not name:
        return "Customer name is required."
    if len(name) > CUSTOMER_NAME_MAX:
        return f"Customer name cannot be longer than {CUSTOMER_NAME_MAX} characters."
    if not re.fullmatch(CUSTOMER_NAME_PATTERN, name):
        return "Customer name must start with a letter or number and can only contain letters, numbers, spaces and . & ' -"
    return None


def validate_customer_contact_details(email, contact):
    """Return an error message for an invalid email or contact number, or None. Both are optional."""
    if email and (len(email) > CUSTOMER_EMAIL_MAX
                  or not re.fullmatch(REGISTRATION_RULES["Email"]["pattern"], email)):
        return "Please enter a valid email address."
    if contact and not re.fullmatch(CUSTOMER_CONTACT_PATTERN, contact):
        return "Contact number must be exactly 10 digits."
    return None


def customer_exists(user_id, customer_name):
    table_name = f"{user_id.lower()}_customers"
    return db.inspect(db.engine).has_table(table_name) and get_customer_record(user_id, customer_name) is not None


@app.route("/add_customer", methods=["POST"])
def add_customer():
    if 'user_id' in session:  # Ensure the user is logged in
        user_id = session['user_id']
        customer_name = clean_customer_name(request.form.get('customer_name'))
        customer_email = request.form.get('customer_email', '').strip()
        customer_contact = request.form.get('customer_contact', '').strip()

        error = validate_customer_name(customer_name) or validate_customer_contact_details(customer_email, customer_contact)
        if error:
            flash(error, "error")
            return redirect(url_for("customer"))

        # Standardize table name
        table_name = f"{user_id.lower()}_customers"  # Lowercase for consistency

        # Dynamic table creation
        engine = db.engine
        metadata = MetaData()

        try:
            # Define or reflect the customer table
            customer_table = Table(
                table_name, metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False, unique=True),
                Column('email', String(100), nullable=False),
                Column('contact', String(20), nullable=False),
                extend_existing=True
            )
            metadata.create_all(engine)  # Create the table if it doesn't exist

            # Insert data into the new table
            with engine.connect() as connection:
                # "Ravi" and "ravi" would share one entries table, so names are unique ignoring case
                duplicate = connection.execute(
                    select(customer_table.c.id).where(db.func.lower(customer_table.c.name) == customer_name.lower())
                ).first()
                if duplicate:
                    raise IntegrityError(None, None, Exception("duplicate customer name"))
                insert_query = customer_table.insert().values(
                    name=customer_name,
                    email=customer_email,
                    contact=customer_contact
                )
                connection.execute(insert_query)  # Execute the insert query
                connection.commit()  # Commit transaction

            flash("Customer added successfully!", "success")  # Toast notification
            return redirect(url_for("customer"))

        except IntegrityError:
            flash("This customer already exists. Please check once.", "error")  # Toast notification
            return redirect(url_for("customer"))

        except Exception as e:
            app.logger.error(f"Error while adding customer: {e}")
            flash("Something went wrong while adding the customer. Please try again.", "error")  # Toast notification
            return redirect(url_for("customer"))

    flash("Unauthorized access. Please log in.", "error")
    return redirect(url_for("login"))

@app.route("/account/<customer_name>")
def account(customer_name):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    b_name = session.get("b_name", "Default Business Name")
    customer_table_name = f"{user_id.lower()}_customers"
    entries_table_name = f"{user_id}_{customer_name.lower()}"
    metadata = MetaData()

    try:
        # Reflect the customer table
        metadata.reflect(bind=db.engine, only=[customer_table_name])
        if customer_table_name not in metadata.tables:
            flash("Customer table does not exist.", "error")
            return redirect(url_for("customer"))

        customer_table = metadata.tables[customer_table_name]

        # Query for the customer
        with db.engine.connect() as connection:
            query = customer_table.select().where(customer_table.c.name == customer_name)
            result = connection.execute(query).fetchone()

        if not result:
            flash("Customer not found.", "error")
            return redirect(url_for("customer"))

        customer = dict(result._mapping)

        # Check if the dynamic table exists
        reflect_existing(metadata, entries_table_name)
        if entries_table_name in metadata.tables:
            entries_table = metadata.tables[entries_table_name]
            with db.engine.connect() as connection:
                entries = connection.execute(entries_table.select()).fetchall()
                entries = [dict(row._mapping) for row in entries]
                overall_total = sum(int(entry["Total"]) for entry in entries if entry["Total"] is not None)

                # overall_total = sum(entry["Total"] for entry in entries)
        else:
            # Create the dynamic table if it doesn't exist
            entries_table = Table(
                entries_table_name,
                metadata,
                Column("id", Integer, primary_key=True, autoincrement=True),
                Column("purchase_date", Date, nullable=False),
                Column("notes", Text, nullable=False),
                Column("items_details", Text, nullable=False),
                Column("Total", Integer, nullable=False),
                Column("due_date", Date, nullable=False),
                extend_existing=True
            )
            metadata.create_all(db.engine)  # Create the table
            entries = []
            overall_total = 0
    except Exception as e:
        app.logger.error(f"Error in account route: {e}")
        flash("Unexpected error occurred.", "error")
        return redirect(url_for("customer"))

    return render_template(
        "account.html",
        customer_name=customer["name"],
        customer_contact=customer["contact"],
        customer_email=customer["email"],
        user_id=user_id,
        b_name=b_name,
        entries=entries,
        overall_total=overall_total,
        reminders={
            r.entry_id: r.recipient
            for r in EntryReminder.query.filter_by(user_id=user_id, customer_name=customer["name"])
        },
    )


@app.route("/add_entry/<customer_name>", methods=["POST"])
def add_entry(customer_name):
    if "user_id" not in session:
        flash("Unauthorized access. Please log in.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    table_name = f"{user_id}_{customer_name.lower()}"  # Table name pattern: user_customer

    # Only create entries for an existing customer (the name comes from the URL)
    if not customer_exists(user_id, customer_name):
        flash("Customer not found.", "error")
        return redirect(url_for("customer"))

    # Collect form data
    purchase_date = request.form.get("pdate")
    notes = request.form.get("notes")
    items_details = request.form.get("items_details")  # Expecting JSON from the form
    due_date = request.form.get("duedate")
    Total = request.form.get("Total")

    if notes and len(notes) > NOTES_MAX_LENGTH:
        flash(f"Notes cannot be longer than {NOTES_MAX_LENGTH} characters.", "error")
        return redirect(url_for("account", customer_name=customer_name))

    # Convert Total to an integer and handle invalid input
    try:
        Total = int(Total)  # Use float(Total) if decimals are required
    except (ValueError, TypeError):
        flash("Invalid Total value. Please enter a numeric value.", "error")
        return redirect(url_for("account", customer_name=customer_name))

    metadata = MetaData()
    engine = db.engine

    try:
        # Define the customer-specific table
        customer_table = Table(
            table_name,
            metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("purchase_date", Date, nullable=False),
            Column("notes", Text, nullable=False),
            Column("items_details", Text, nullable=False),
            Column("Total", Integer, nullable=False),
            Column("due_date", Date, nullable=False),
            extend_existing=True
        )
        metadata.create_all(engine)  # Ensure table is created

        # Insert the new entry
        with engine.connect() as connection:
            with connection.begin():
                insert_query = customer_table.insert().values(
                    purchase_date=purchase_date,
                    notes=notes,
                    Total=Total,
                    items_details=items_details,
                    due_date=due_date
                )
                result = connection.execute(insert_query)
                app.logger.info(f"Insert result: {result.rowcount} rows affected.")

        flash("Entry added successfully!", "success")
        return redirect(url_for("account", customer_name=customer_name))

    except Exception as e:
        app.logger.error(f"Error while adding entry: {e}")
        flash("An error occurred while adding the entry.", "error")
        return redirect(url_for("account", customer_name=customer_name))


# @app.route("/add_entry/<customer_name>", methods=["POST"])
# def add_entry(customer_name):
#     if "user_id" not in session:
#         flash("Unauthorized access. Please log in.", "error")
#         return redirect(url_for("login"))

#     user_id = session["user_id"]
#     table_name = f"{user_id}_{customer_name.lower()}"  # Table name pattern: user_customer

#     # Collect form data
#     purchase_date = request.form.get("pdate")
#     notes = request.form.get("notes")
#     items_json = request.form.get("items")  # Expecting JSON from the form
#     due_date = request.form.get("duedate")

#     # Parse items JSON
#     try:
#         items = json.loads(items_json) if items_json else []
#     except Exception as e:
#         app.logger.error(f"Error parsing items JSON: {e}")
#         flash(f"Error parsing items: {e}", "error")
#         return redirect(url_for("account", customer_name=customer_name))

#     # Calculate total from items
#     total = sum(float(item["price"]) for item in items) if items else 0.0

#     metadata = MetaData()
#     engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])

#     try:
#         # Define the customer-specific table
#         customer_table = Table(
#             table_name,
#             metadata,
#             Column("id", Integer, primary_key=True, autoincrement=True),
#             Column("purchase_date", Date, nullable=False),
#             Column("notes", Text, nullable=False),
#             Column("items", JSON if engine.dialect.name != "sqlite" else Text, nullable=False),
#             Column("due_date", Date, nullable=False),
#             Column("total", Float, nullable=False),
#             extend_existing=True
#         )
#         metadata.create_all(engine)  # Ensure table is created

#         # Log the data being inserted
#         app.logger.info(f"Preparing to insert into table {table_name}:")
#         app.logger.info(f"purchase_date={purchase_date}, notes={notes}, items={items}, due_date={due_date}, total={total}")

#         # Insert the new entry
#         with engine.connect() as connection:
#           with connection.begin():
#             insert_query = customer_table.insert().values(
#                 purchase_date=purchase_date,
#                 notes=notes,
#                 items=json.dumps(items),  # Store as JSON (or string for SQLite)
#                 due_date=due_date,
#                 total=total
#             )
#             result = connection.execute(insert_query)
#             app.logger.info(f"Insert result: {result.rowcount} rows affected.")

#         flash("Entry added successfully!", "success")
#         return redirect(url_for("account", customer_name=customer_name))

#     except Exception as e:
#         app.logger.error(f"Error while adding entry: {e}")
#         flash("An error occurred while adding the entry.", "error")
#         return redirect(url_for("account", customer_name=customer_name))

@app.route("/delete_entry/<customer_name>/<int:entry_id>", methods=["POST"])
def delete_entry(customer_name, entry_id):
    if "user_id" not in session:
        flash("Unauthorized access. Please log in.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    table_name = f"{user_id}_{customer_name.lower()}"

    metadata = MetaData()
    engine = db.engine

    try:
        # Reflect the dynamic table
        metadata.reflect(bind=engine)
        if table_name not in metadata.tables:
            flash("Table not found.", "error")
            return redirect(url_for("account", customer_name=customer_name))

        entries_table = metadata.tables[table_name]

        # Delete the entry
        with engine.connect() as connection:
            with connection.begin():
                delete_query = entries_table.delete().where(entries_table.c.id == entry_id)
                result = connection.execute(delete_query)
                if result.rowcount > 0:
                    flash("Entry deleted successfully!", "success")
                else:
                    flash("Entry not found.", "error")

    except Exception as e:
        app.logger.error(f"Error while deleting entry: {e}")
        flash("An error occurred while deleting the entry.", "error")

    return redirect(url_for("account", customer_name=customer_name))

@app.route("/delete_customer/<int:customer_id>", methods=["POST"])
def delete_customer(customer_id):
    if "user_id" not in session:
        flash("Unauthorized access. Please log in.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    customer_table_name = f"{user_id.lower()}_customers"
    metadata = MetaData()

    try:
        # Reflect metadata to ensure table exists
        reflect_existing(metadata, customer_table_name)

        # Check if the customer table exists
        if customer_table_name not in metadata.tables:
            app.logger.error(f"Customer table {customer_table_name} not found.")
            flash("Customer table not found.", "error")
            return redirect(url_for("customer"))

        customer_table = metadata.tables[customer_table_name]

        # Fetch customer details as a dictionary
        with db.engine.connect() as connection:
            customer_query = select(customer_table).where(customer_table.c.id == customer_id)
            customer = connection.execute(customer_query).mappings().fetchone()

        if not customer:
            app.logger.error(f"Customer ID {customer_id} not found in table {customer_table_name}.")
            flash("Customer not found.", "error")
            return redirect(url_for("customer"))

        customer_name = customer["name"]
        dynamic_table_name = f"{user_id}_{customer_name.lower()}"
        reflect_existing(metadata, dynamic_table_name)

        # Drop the dynamic table if it exists
        app.logger.debug(f"Checking for dynamic table: {dynamic_table_name}")
        if dynamic_table_name in metadata.tables:
            dynamic_table = metadata.tables[dynamic_table_name]
            with db.engine.connect() as connection:
                app.logger.debug(f"Dropping dynamic table: {dynamic_table_name}")
                dynamic_table.drop(db.engine)

        # Delete the customer from the customers table
        with db.engine.connect() as connection:
            with connection.begin():
                delete_query = customer_table.delete().where(customer_table.c.id == customer_id)
                result = connection.execute(delete_query)
                app.logger.debug(f"Delete query executed: {result.rowcount} rows affected")

        if result.rowcount > 0:
            app.logger.info(f"Successfully deleted customer ID {customer_id} from {customer_table_name}.")
            return jsonify({"message": "Customer deleted successfully."}), 200
        else:
            app.logger.error(f"No rows deleted for customer ID {customer_id} in {customer_table_name}.")
            return jsonify({"error": "Deletion failed, no rows affected."}), 500

    except Exception as e:
        app.logger.error(f"Error while deleting customer: {e}")
        return jsonify({"error": "Something went wrong while deleting the customer."}), 500


@app.route("/update_customer/<customer_name>", methods=["POST"])
def update_customer(customer_name):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    user_id = session["user_id"]
    table_name = f"{user_id.lower()}_customers"
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip()
    contact = str(data.get("contact") or "").strip()

    error = validate_customer_contact_details(email, contact)
    if error:
        return jsonify({"error": error}), 400

    metadata = MetaData()
    try:
        # Reflect the customer table
        metadata.reflect(bind=db.engine, only=[table_name])
        customer_table = metadata.tables[table_name]

        # Update the specific customer's details
        with db.engine.connect() as connection:
            update_query = customer_table.update().where(
                customer_table.c.name == customer_name
            ).values(
                contact=contact,
                email=email
            )
            connection.execute(update_query)
            connection.commit()  # Commit transaction

        return jsonify({"success": "Customer details updated successfully"}), 200

    except Exception as e:
        app.logger.error(f"Error while updating customer: {e}")
        return jsonify({"error": "An error occurred while updating"}), 500


@app.route("/get_entry/<customer_name>/<int:entry_id>", methods=["GET"])
def get_entry(customer_name, entry_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized access"}), 403

    user_id = session["user_id"]
    table_name = f"{user_id}_{customer_name.lower()}"

    metadata = MetaData()
    engine = db.engine

    try:
        customer_table = Table(table_name, metadata, autoload_with=engine)

        with engine.connect() as connection:
            query = customer_table.select().where(customer_table.c.id == entry_id)
            result = connection.execute(query).fetchone()

        if result:
          # Convert SQLAlchemy result to dictionary
          result_dict = dict(result._mapping)

    # Format date fields
        if "purchase_date" in result_dict and result_dict["purchase_date"]:
          result_dict["purchase_date"] = result_dict["purchase_date"].strftime("%Y-%m-%d")
        if "due_date" in result_dict and result_dict["due_date"]:
          result_dict["due_date"] = result_dict["due_date"].strftime("%Y-%m-%d")

    # Rename Total to total
        if "Total" in result_dict:
         result_dict["total"] = result_dict.pop("Total")

        return jsonify(result_dict)
    except Exception as e:
        app.logger.error(f"Error occurred: {e}")
        return jsonify({"error": "Unexpected error occurred"}), 500

@app.route("/update_entry/<customer_name>", methods=["POST"])
def update_entry(customer_name):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized access"}), 403

    user_id = session["user_id"]
    entry_id = request.form.get("entry_id")
    purchase_date = request.form.get("pdate") or None
    notes = request.form.get("notes")
    items_details = request.form.get("items_details")
    total = request.form.get("Total")
    try:
        total = int(total) if total else 0
    except (ValueError, TypeError):
        total = 0
    due_date = request.form.get("duedate") or None

    app.logger.debug(f"Received form data: {request.form}")

    if notes and len(notes) > NOTES_MAX_LENGTH:
        return jsonify({"error": f"Notes cannot be longer than {NOTES_MAX_LENGTH} characters."}), 400

    try:
        # Validate entry_id
        entry_id = int(entry_id)
    except (ValueError, TypeError):
        app.logger.error("Invalid entry_id provided.")
        return jsonify({"error": "Invalid entry_id"}), 400

    metadata = MetaData()
    engine = db.engine
    table_name = f"{user_id}_{customer_name.lower()}"

    try:
        # Reflect the table to ensure it exists
        customer_table = Table(table_name, metadata, autoload_with=engine)

        with engine.connect() as connection:
            update_query = (
                customer_table.update()
                .where(customer_table.c.id == entry_id)
                .values(
                    purchase_date=purchase_date,
                    notes=notes,
                    items_details=items_details,
                    Total=total,  # Match the column name in the database
                    due_date=due_date,
                )
            )
            result = connection.execute(update_query)
            connection.commit()
            app.logger.debug(f"Update query executed. Rows affected: {result.rowcount}")

        if result.rowcount > 0:
            return jsonify({"message": "Entry updated successfully"})
        else:
            app.logger.warning(f"No rows updated for entry_id: {entry_id}")
            return jsonify({"error": "No rows updated. Check entry_id or data."}), 400
    except Exception as e:
        app.logger.error(f"Error occurred: {e}")
        return jsonify({"error": "Unexpected error occurred"}), 500

#sending mail
# ---------------------------------------------------------------------------
# Payment reminders
#
# The bell menu on the account page offers three options per entry:
#   "Email now"        -> email the customer immediately
#   "On the due date"  -> email the customer at 12:00 AM on the entry's due date
#   "Remind me"        -> email the business owner at 12:00 AM on the due date
# Scheduled reminders are stored in the entry_reminders table and removed once
# the email has been sent successfully (or when the user clears them).
# ---------------------------------------------------------------------------
sender_email = require_env("MAIL_USERNAME")
sender_password = require_env("MAIL_PASSWORD")  # Gmail app password

REMINDER_RECIPIENTS = ("customer", "owner")


def get_customer_record(user_id, customer_name):
    """Return the customer's row from <user>_customers as a dict, or None."""
    table_name = f"{user_id.lower()}_customers"
    metadata = MetaData()
    metadata.reflect(bind=db.engine, only=[table_name], extend_existing=True)
    customers_table = metadata.tables[table_name]
    with db.engine.connect() as connection:
        row = connection.execute(
            select(customers_table).where(customers_table.c.name == customer_name)
        ).mappings().fetchone()
    return dict(row) if row else None


def get_entry_record(user_id, customer_name, entry_id):
    """Return (entry dict, outstanding total for the customer), or (None, 0)."""
    table_name = f"{user_id}_{customer_name.lower()}"
    if not db.inspect(db.engine).has_table(table_name):
        return None, 0  # entries table no longer exists (customer deleted)
    metadata = MetaData()
    metadata.reflect(bind=db.engine, only=[table_name], extend_existing=True)
    entries_table = metadata.tables[table_name]
    with db.engine.connect() as connection:
        entry = connection.execute(
            select(entries_table).where(entries_table.c.id == entry_id)
        ).mappings().fetchone()
        outstanding = connection.execute(
            select(db.func.coalesce(db.func.sum(entries_table.c.Total), 0))
        ).scalar()
    return (dict(entry) if entry else None), int(outstanding or 0)


def format_rupees(amount):
    return f"₹ {int(amount or 0):,}"


def format_short_date(value):
    return value.strftime("%d-%m-%y") if value else "—"


def build_reminder_email(recipient, b_name, customer_name, entry, outstanding):
    """Build (subject, html, text) for a payment reminder."""
    amount = format_rupees(entry["Total"])
    context = {
        "recipient": recipient,
        "b_name": b_name,
        "customer_name": customer_name,
        "amount": amount,
        "outstanding": format_rupees(outstanding),
        "purchase_date": format_short_date(entry["purchase_date"]),
        "due_date": format_short_date(entry["due_date"]),
        "notes": entry["notes"],
        "items": entry["items_details"],
    }

    if recipient == "owner":
        subject = f"Reminder: {customer_name} has {amount} due today"
        text = (
            f"Hi {b_name},\n\n"
            f"This is your reminder that {customer_name} has a pending payment of {amount} "
            f"due on {context['due_date']}.\n\n"
            f"Purchase date: {context['purchase_date']}\n"
            f"Notes: {context['notes']}\n"
            f"Items: {context['items']}\n"
            f"Total outstanding from {customer_name}: {context['outstanding']}\n\n"
            f"- Bill Up"
        )
    else:
        subject = f"Payment reminder from {b_name}: {amount} due on {context['due_date']}"
        text = (
            f"Dear {customer_name},\n\n"
            f"This is a gentle reminder from {b_name} about a pending payment of {amount}, "
            f"due on {context['due_date']}.\n\n"
            f"Purchase date: {context['purchase_date']}\n"
            f"Notes: {context['notes']}\n"
            f"Items: {context['items']}\n"
            f"Total outstanding: {context['outstanding']}\n\n"
            f"If you have already paid, please ignore this email.\n\n"
            f"Thank you,\n{b_name}"
        )

    html = render_template("emails/payment_reminder.html", **context)
    return subject, html, text


def build_email_message(to_address, subject, html, text):
    msg = MIMEMultipart("alternative")
    msg["From"] = sender_email
    msg["To"] = to_address
    # Header() encodes non-ASCII characters such as "₹", which smtplib rejects in raw headers
    msg["Subject"] = Header(subject, "utf-8")
    # flask_mail switches the global utf-8 charset to raw 8-bit bodies, which
    # smtplib cannot send; base64 keeps the whole message ASCII-safe
    body_charset = Charset("utf-8")
    body_charset.body_encoding = BASE64
    msg.attach(MIMEText(text, "plain", body_charset))
    msg.attach(MIMEText(html, "html", body_charset))
    return msg


def send_email(to_address, subject, html, text):
    """Send an HTML email (with a plain-text fallback). Raises on failure."""
    msg = build_email_message(to_address, subject, html, text)

    server = smtplib.SMTP("smtp.gmail.com", 587, timeout=30)
    try:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, [to_address], msg.as_string())
    finally:
        server.quit()


def send_entry_reminder(user_id, customer_name, entry_id, recipient):
    """Email a reminder for one entry. Raises ValueError with a user-facing message."""
    owner = Registration.query.filter_by(UserID=user_id).first()
    if not owner:
        raise ValueError("Business account not found.")

    entry, outstanding = get_entry_record(user_id, customer_name, entry_id)
    if not entry:
        raise ValueError("This entry no longer exists.")

    if recipient == "owner":
        to_address = owner.Email
    else:
        customer = get_customer_record(user_id, customer_name)
        to_address = customer["email"] if customer else None
    if not to_address:
        raise ValueError(
            "This customer has no email address. Add one with \"Edit details\"."
            if recipient == "customer" else "Your account has no email address."
        )

    subject, html, text = build_reminder_email(recipient, owner.bName, customer_name, entry, outstanding)
    try:
        send_email(to_address, subject, html, text)
    except Exception as e:
        app.logger.error(f"Failed to send reminder to {to_address}: {e}")
        raise ValueError("The email could not be sent. Please try again.") from e
    app.logger.info(f"Reminder for entry {entry_id} ({customer_name}) sent to {to_address}")


@app.route("/reminder/<customer_name>/<int:entry_id>", methods=["POST"])
def entry_reminder(customer_name, entry_id):
    """Handle the bell menu: send now, schedule for the due date, or clear."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized access"}), 403

    user_id = session["user_id"]
    action = (request.get_json(silent=True) or {}).get("action")

    if action == "email_now":
        try:
            send_entry_reminder(user_id, customer_name, entry_id, "customer")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"message": "Customer notified by email."})

    existing = EntryReminder.query.filter_by(
        user_id=user_id, customer_name=customer_name, entry_id=entry_id
    ).first()

    if action == "clear":
        if existing:
            db.session.delete(existing)
            db.session.commit()
        return jsonify({"message": "Reminder cleared."})

    if action not in ("customer_due", "owner_due"):
        return jsonify({"error": "Unknown reminder option."}), 400

    entry, _ = get_entry_record(user_id, customer_name, entry_id)
    if not entry:
        return jsonify({"error": "This entry no longer exists."}), 404
    if not entry["Total"]:
        return jsonify({"error": "This entry is already paid, so no reminder is needed."}), 400
    if entry["due_date"] <= date.today():
        return jsonify({"error": "The due date is today or has passed. Use \"Email now\" instead."}), 400

    recipient = "customer" if action == "customer_due" else "owner"
    if recipient == "customer":
        customer = get_customer_record(user_id, customer_name)
        if not customer or not customer.get("email"):
            return jsonify({"error": "This customer has no email address. Add one with \"Edit details\"."}), 400

    # One scheduled reminder per entry: choosing another option replaces it
    if existing:
        existing.recipient = recipient
        existing.last_error = None
    else:
        db.session.add(EntryReminder(
            user_id=user_id, customer_name=customer_name, entry_id=entry_id, recipient=recipient
        ))
    db.session.commit()

    who = "the customer" if recipient == "customer" else "you"
    return jsonify({
        "message": f"Reminder set. An email will go to {who} at 12:00 AM on {format_short_date(entry['due_date'])}.",
        "recipient": recipient,
    })


def send_due_reminders():
    """Send every scheduled reminder whose entry is due today (or overdue).

    Runs at 12:00 AM and then hourly, so a reminder that failed (for example
    because there was no internet) is retried until it is sent.
    """
    with app.app_context():
        today = date.today()
        for reminder in EntryReminder.query.all():
            try:
                entry, _ = get_entry_record(reminder.user_id, reminder.customer_name, reminder.entry_id)
                if not entry or not entry["Total"]:
                    # Entry deleted or already paid: nothing to remind about
                    db.session.delete(reminder)
                    continue
                if entry["due_date"] > today:
                    continue

                send_entry_reminder(reminder.user_id, reminder.customer_name, reminder.entry_id, reminder.recipient)
                db.session.delete(reminder)
            except Exception as e:
                reminder.last_error = str(e)
                reminder.last_attempt = datetime.now()
                app.logger.error(f"Reminder {reminder.id} not sent: {e}")
        db.session.commit()


scheduler = BackgroundScheduler()
# Every hour on the hour, starting at 12:00 AM; the first run on the due date is midnight
scheduler.add_job(func=send_due_reminders, trigger="cron", minute=0,
                  id="due_reminders", coalesce=True, misfire_grace_time=3600)

# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
ADMIN_USERNAME = require_env("ADMIN_USERNAME")
ADMIN_PASSWORD = require_env("ADMIN_PASSWORD")
ADMIN_FIELD_MAX = 128  # Longest admin ID / password the login form accepts
assert len(ADMIN_USERNAME) <= ADMIN_FIELD_MAX and len(ADMIN_PASSWORD) <= ADMIN_FIELD_MAX
app.jinja_env.globals["ADMIN_FIELD_MAX"] = ADMIN_FIELD_MAX


def admin_required(view):
    """Send visitors who have not logged in as admin to the admin login page."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            if request.method != "GET" or request.is_json:
                return jsonify({"error": "Admin login required."}), 403
            return redirect(url_for("AdminLog"))
        return view(*args, **kwargs)
    return wrapper


@app.route('/AdminLog', methods=["GET", "POST"])
def AdminLog():
    if session.get("is_admin") and request.method == "GET":
        return redirect(url_for("AdminDash"))

    if request.method == "POST":
        user_id = request.form.get("UserID", "").strip()[:ADMIN_FIELD_MAX]
        password = request.form.get("Password", "")[:ADMIN_FIELD_MAX + 1]  # One extra so an over-long password fails

        locked_minutes = login_locked_minutes("admin", user_id)
        if locked_minutes:
            return render_template("AdminLog.html", alert_message=too_many_attempts_message(locked_minutes)), 429

        # compare_digest takes the same time whether or not the first characters match
        if (hmac.compare_digest(user_id.encode(), ADMIN_USERNAME.encode())
                and hmac.compare_digest(password.encode(), ADMIN_PASSWORD.encode())):
            clear_login_failures("admin", user_id)
            session["is_admin"] = True
            session["admin_id"] = user_id
            return redirect(url_for("AdminDash"))

        record_login_failure("admin", user_id)
        return render_template(
            "AdminLog.html",
            alert_message="Invalid UserID or Password. Please try again."
        )

    return render_template("AdminLog.html")


@app.route('/AdminLogout')
def AdminLogout():
    # Only end the admin session; a business owner logged in on the same browser stays logged in
    session.pop("is_admin", None)
    session.pop("admin_id", None)
    return redirect(url_for("AdminLog"))


def business_tables(user_id, existing_tables):
    """Return (customers table name, [entries table names]) that belong to one business.

    Names are built exactly the way the rest of the app builds them, so no other
    business's tables can be matched by accident.
    """
    customers_table = f"{user_id.lower()}_customers"
    entry_tables = []
    if customers_table in existing_tables:
        metadata = MetaData()
        metadata.reflect(bind=db.engine, only=[customers_table])
        with db.engine.connect() as connection:
            names = connection.execute(select(metadata.tables[customers_table].c.name)).scalars().all()
        entry_tables = [f"{user_id}_{name.lower()}" for name in names]
    return customers_table, entry_tables


def business_stats(user_id, existing_tables):
    """Customers, entries, pending entries and outstanding amount for one business."""
    customers_table, entry_tables = business_tables(user_id, existing_tables)
    stats = {"customers": 0, "entries": 0, "pending": 0, "outstanding": 0}
    if customers_table not in existing_tables:
        return stats
    stats["customers"] = len(entry_tables)
    with db.engine.connect() as connection:
        for table_name in entry_tables:
            if table_name not in existing_tables:
                continue
            quoted = db.engine.dialect.identifier_preparer.quote(table_name)
            row = connection.exec_driver_sql(
                f'SELECT COUNT(*), COUNT(*) FILTER (WHERE "Total" <> 0), COALESCE(SUM("Total"), 0) FROM {quoted}'
            ).fetchone()
            stats["entries"] += row[0]
            stats["pending"] += row[1]
            stats["outstanding"] += int(row[2])
    return stats


#Admin Dashboard Route
@app.route('/AdminDash')
@admin_required
def AdminDash():
    try:
        existing_tables = set(db.inspect(db.engine).get_table_names())
        reminder_counts = dict(
            db.session.query(EntryReminder.user_id, db.func.count(EntryReminder.id))
            .group_by(EntryReminder.user_id).all()
        )

        businesses = []
        for reg in Registration.query.order_by(Registration.JoinDate.desc()).all():
            stats = business_stats(reg.UserID, existing_tables)
            businesses.append({
                "id": reg.id,
                "user_id": reg.UserID,
                "name": reg.bName,
                "type": reg.bType or "",
                "address": reg.bAddress,
                "email": reg.Email,
                "contact": reg.Contact,
                "joined": reg.JoinDate,
                "reminders": reminder_counts.get(reg.UserID, 0),
                **stats,
            })

        # Sign-ups per month for the last 6 months (oldest first) for the chart
        today = date.today()
        months = []
        for back in range(5, -1, -1):
            year, month = today.year, today.month - back
            while month <= 0:
                month += 12
                year -= 1
            months.append((year, month))
        signup_counts = {m: 0 for m in months}
        for b in businesses:
            if b["joined"] and (b["joined"].year, b["joined"].month) in signup_counts:
                signup_counts[(b["joined"].year, b["joined"].month)] += 1
        chart = {
            "labels": [date(y, m, 1).strftime("%b %Y") for y, m in months],
            "values": [signup_counts[m] for m in months],
        }

        this_month = (today.year, today.month)
        totals = {
            "businesses": len(businesses),
            "new_this_month": signup_counts[this_month],
            "customers": sum(b["customers"] for b in businesses),
            "entries": sum(b["entries"] for b in businesses),
            "outstanding": sum(b["outstanding"] for b in businesses),
            "reminders": sum(b["reminders"] for b in businesses),
        }
        top_outstanding = sorted(
            (b for b in businesses if b["outstanding"] > 0), key=lambda b: b["outstanding"], reverse=True
        )[:5]

        return render_template(
            "AdminDash.html",
            businesses=businesses,
            totals=totals,
            chart=chart,
            top_outstanding=top_outstanding,
            admin_id=session.get("admin_id", "Admin"),
        )
    except Exception as e:
        logging.error(f"Error loading admin dashboard: {e}")
        return "Error loading dashboard", 500


@app.route("/delete_registration/<user_id>", methods=["POST"])
@admin_required
def delete_registration(user_id):
    """Delete a business, its customers table, every customer's entries table and its reminders."""
    reg = Registration.query.filter_by(UserID=user_id).first()
    if not reg:
        return jsonify({"error": "Business not found."}), 404

    try:
        existing_tables = set(db.inspect(db.engine).get_table_names())
        customers_table, entry_tables = business_tables(user_id, existing_tables)
        to_drop = [t for t in entry_tables + [customers_table] if t in existing_tables]

        metadata = MetaData()
        for table_name in to_drop:
            Table(table_name, metadata, autoload_with=db.engine).drop(db.engine)
            app.logger.info(f"Dropped table: {table_name}")

        EntryReminder.query.filter_by(user_id=user_id).delete()
        db.session.delete(reg)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting business {user_id}: {e}")
        return jsonify({"error": "An error occurred while deleting this business."}), 500

    return jsonify({"message": f"{reg.bName} and all of its data were deleted."})


@app.route("/About.html")
def About():
    return render_template("About.html")

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):  # 404, 405... keep their own status
        return e
    app.logger.exception(f"Error occurred: {e}")
    return "An unexpected error occurred. Please try again.", 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    if DEBUG:
        # Development: Flask's auto-reloading server. With debug on, the reloader
        # runs this file twice (a watcher process and the real server); start the
        # scheduler only in the server process, otherwise every reminder email
        # would be sent twice.
        if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            scheduler.start()
            atexit.register(lambda: scheduler.shutdown())  # Graceful shutdown on exit
        app.run(debug=True)
    else:
        # Live: Waitress, a production server. It runs a single process (with
        # several threads), so the reminder scheduler runs exactly once.
        from waitress import serve

        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())
        host = os.environ.get("HOST", "0.0.0.0")
        port = int(os.environ.get("PORT", "5000"))
        app.logger.info(f"Bill Up running on http://{host}:{port}")
        serve(app, host=host, port=port, threads=8)
