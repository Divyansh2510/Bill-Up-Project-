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
from werkzeug.security import generate_password_hash,check_password_hash
import json
import pymysql
import os
import math
from sqlalchemy import select
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, DateField, IntegerField
from wtforms.validators import DataRequired
from sqlalchemy import or_
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, date
import atexit
from google.cloud import translate_v2 as translate

app = Flask(__name__)
app.secret_key = 'super-secret-key'  # Add a secret key for session handling if needed
logging.basicConfig(level=logging.DEBUG)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Djain1234@localhost/Bill Up'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Registration(db.Model):
    __tablename__ = 'Registeration'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    JoinDate = db.Column(db.DateTime, default=datetime.utcnow)
    bName = db.Column(db.String(100), nullable=False)
    bAddress = db.Column(db.String(200), nullable=False)
    bType = db.Column(db.String(20), nullable=True)
    UserID = db.Column(db.String(20), nullable=False)
    Email = db.Column(db.String(50), nullable=False)
    Contact = db.Column(db.Integer, nullable=False)
    Password = db.Column(db.String(15), nullable=False)

@app.route("/")
def index():
    
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Handlimg login form submission
        user_id = request.form.get("UserID")  # Get UserId from form input
        password = request.form.get("Password")  # Get Password from form input

        # Query user from the database
        user = Registration.query.filter_by(UserID=user_id).first()

        # Validate user credentials
        if user and check_password_hash(user.Password, password): 
            session["user_id"] = user.UserID  # Save user info in the session
            session["b_name"] = user.bName
            return redirect(url_for("customer"))  

        # Invalid credentials
        return render_template(
            "login.html", 
            alert_message="Invalid UserID or Password. Please try again."
        )

    # Render login page for GET requests
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()  
    return redirect(url_for('index'))  


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Collect form data
        bName = request.form.get("bName")
        bAddress = request.form.get("bAddress")
        bType = request.form.get("bType")
        UserID = request.form.get("UserID")
        Email = request.form.get("Email")
        Contact = request.form.get("Contact")
        password = request.form.get("Password")
        confirm_password = request.form.get("ConfirmPassword")

        form_data = {
            "bName": bName,
            "bAddress": bAddress,
            "bType": bType,
            "UserID": UserID,
            "Email": Email,
            "Contact": Contact,
        }

        existing_user = Registration.query.filter_by(UserID=UserID).first()
        if existing_user:
            return render_template(
                "register.html",
                alert_message="UserID already exists. Please choose a different one!",
                form_data=request.form
            )

        existing_pass = Registration.query.filter_by(Password=password).first()
        if existing_pass:
            return render_template(
                "register.html",
                alert_message= "These password is unavailable!! Use special characters or symbols  in password.",
                form_data=request.form
            )

        if len(password) > 8:
            return render_template(
                "register.html",
                alert_message="Password cannot exceed 8 characters!",
                form_data=request.form.to_dict()
            )


        # Check if password and confirm_password match
        if password != confirm_password:
             return render_template(
                "register.html",
                alert_message="Passwords do not match!",
                form_data=form_data,
                
            )

        # Save data to the database (if passwords match)
        hashed_password = generate_password_hash(password) 
        new_registration = Registration(
            bName=bName,
            bAddress=bAddress,
            bType=bType,
            UserID=UserID,
            Email=Email,
            Contact=int(Contact),
            Password=hashed_password
        )
        db.session.add(new_registration)
        db.session.commit()

        # Redirect to login page after successful registration
        return redirect(url_for("login"))

    return render_template("register.html")


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
        metadata.reflect(bind=db.engine, only=[table_name])

        if table_name not in metadata.tables:
            print(f"Table {table_name} does not exist.")
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
                # Add a filter to the query for the search functionality
                query = query.where(
                    db.func.lower(customer_table.c.name).like(f"%{search_query}%")
                )

            result = connection.execute(query)

            # Fetch column names and rows
            column_names = result.keys()
            customers = [dict(zip(column_names, row)) for row in result]

        # Calculate overall_total for each customer and the total sum
        for customer in customers:
            customer_name = customer["name"]
            entries_table_name = f"{user_id}_{customer_name.lower()}"
            metadata.reflect(bind=db.engine)

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
        print(f"Error occurred: {e}")
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


@app.route("/add_customer", methods=["POST"])
def add_customer():
    if 'user_id' in session:  # Ensure the user is logged in
        user_id = session['user_id']
        customer_name = request.form['customer_name']
        customer_email = request.form['customer_email']
        customer_contact = request.form['customer_contact']

        # Standardize table name
        table_name = f"{user_id.lower()}_customers"  # Lowercase for consistency

        # Dynamic table creation
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
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
            flash(f"Unexpected Error: {str(e)}", "error")  # Toast notification
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
        metadata.reflect(bind=db.engine)
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
        overall_total=overall_total 
    )


@app.route("/add_entry/<customer_name>", methods=["POST"])
def add_entry(customer_name):
    if "user_id" not in session:
        flash("Unauthorized access. Please log in.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    table_name = f"{user_id}_{customer_name.lower()}"  # Table name pattern: user_customer

    # Collect form data
    purchase_date = request.form.get("pdate")
    notes = request.form.get("notes")
    items_details = request.form.get("items_details")  # Expecting JSON from the form
    due_date = request.form.get("duedate")
    Total = request.form.get("Total")

    # Convert Total to an integer and handle invalid input
    try:
        Total = int(Total)  # Use float(Total) if decimals are required
    except (ValueError, TypeError):
        flash("Invalid Total value. Please enter a numeric value.", "error")
        return redirect(url_for("account", customer_name=customer_name))

    metadata = MetaData()
    engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])

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
    engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])

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
        metadata.reflect(bind=db.engine)
        app.logger.debug(f"Available tables: {metadata.tables.keys()}")

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
        return jsonify({"error": str(e)}), 500


@app.route("/update_customer/<customer_name>", methods=["POST"])
def update_customer(customer_name):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    user_id = session["user_id"]
    table_name = f"{user_id.lower()}_customers"
    data = request.get_json()

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
                contact=data["contact"],
                email=data["email"]
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
    engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])

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

    try:
        # Validate entry_id
        entry_id = int(entry_id)
    except (ValueError, TypeError):
        app.logger.error("Invalid entry_id provided.")
        return jsonify({"error": "Invalid entry_id"}), 400

    metadata = MetaData()
    engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])
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
@app.route("/send_mail", methods=["POST"])
def send_mail():
    # Parse the request data
    data = request.get_json()
    customer_email = data.get("email")
    customer_name = data.get("name")
    b_name = data.get("b_name")
    overall_total = data.get("overall_total")
    purchase_date = data.get("purchase_date")
    items_details = data.get("items_details")
    total = data.get("total")

    # Email credentials (set email credentials here)
    sender_email = "divyanhjain@gmail.com"  
    sender_password = "uwwn evdk xjxn zlag"  
    subject = "Bill Up Notification"
    body = f"Dear {customer_name},\n\nA Gentle Remainder from {b_name} !!\n\n " \
           f"You have pending payment of Rupees {total} of items purchased on Date : {purchase_date}\n\n " \
           f"The items are : {items_details}\n\n" \
           f"Payable Total:{total}\n\n" \
           f"Also Your Sum of all Previous Pending Purchases still left are : {overall_total}\n\n " \
           f"Keep Shopping with us . Thank You !!\n\n" \
           f"Best regards,\nBill Up Team"

    try:
        # Set up the email server and login
        server = smtplib.SMTP("smtp.gmail.com", 587)  
        server.starttls()  # Upgrade the connection to secure
        server.login(sender_email, sender_password)

        # Create the email message
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = customer_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        # Send the email
        server.sendmail(sender_email, customer_email, msg.as_string())
        server.quit()

        return jsonify({"message": "Email sent successfully"})
    
    except Exception as e:
        app.logger.error(f"Error occurred: {e}")
        return jsonify({"error": "Unexpected error occurred"}), 500
    
sender_email = "divyanhjain@gmail.com"
sender_password = "uwwn evdk xjxn zlag"

def send_due_emails():
    with app.app_context():
        engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])
        metadata = MetaData()
        metadata.reflect(bind=engine)

        # Loop through all tables to find *_customers and related *_<customer> tables
        for table_name in metadata.tables:
            if table_name.endswith("_customers"):
                user_id = table_name.replace("_customers", "")
                customers_table = metadata.tables[table_name]

                with engine.connect() as connection:
                    customer_rows = connection.execute(select(customers_table)).fetchall()

                    for customer in customer_rows:
                        customer_name = customer['name']
                        customer_email = customer['email']
                        contact_table_name = f"{user_id}_{customer_name.lower()}"

                        if contact_table_name in metadata.tables:
                            entries_table = metadata.tables[contact_table_name]
                            today = date.today()

                            due_entries = connection.execute(
                                select(entries_table).where(entries_table.c.due_date == today)
                            ).fetchall()

                            for entry in due_entries:
                                # Calculate overall_total
                                total_query = select([entries_table.c.Total])
                                all_entries = connection.execute(total_query).fetchall()
                                overall_total = sum(int(row["Total"]) for row in all_entries if row["Total"])

                                # Compose and send the email
                                body = f"Dear {customer_name},\n\nA Gentle Remainder from {user_id} !!\n\n " \
                                       f"You have pending payment of Rupees {entry['Total']} of items purchased on Date : {entry['purchase_date']}\n\n " \
                                       f"The items are : {entry['items_details']}\n\n" \
                                       f"Payable Total:{entry['Total']}\n\n" \
                                       f"Also Your Sum of all Previous Pending Purchases still left are : {overall_total}\n\n " \
                                       f"Keep Shopping with us . Thank You !!\n\n" \
                                       f"Best regards,\nBill Up Team"

                                try:
                                    server = smtplib.SMTP("smtp.gmail.com", 587)
                                    server.starttls()
                                    server.login(sender_email, sender_password)

                                    msg = MIMEMultipart()
                                    msg["From"] = sender_email
                                    msg["To"] = customer_email
                                    msg["Subject"] = "Bill Up Notification"
                                    msg.attach(MIMEText(body, "plain"))

                                    server.sendmail(sender_email, customer_email, msg.as_string())
                                    server.quit()

                                    app.logger.info(f"Due date email sent to {customer_email}")

                                except Exception as e:
                                    app.logger.error(f"Failed to send email to {customer_email}: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(func=send_due_emails, trigger="cron", hour=9, minute=0)  # Runs daily at 9:00 AM
# scheduler.start()

#Admin Login Route
@app.route('/AdminLog', methods=["GET", "POST"])
def AdminLog():
    
    if request.method == "POST":
        # Handle login form submission
        user_id = request.form.get("UserID")  
        password = request.form.get("Password")  

        # Validate user credentials
        if user_id=="Djain" and password=="25102004" : 
            
            return redirect(url_for("AdminDash"))  # Redirect to the main page after login

        # Invalid credentials
        return render_template(
            "AdminLog.html", 
            alert_message="Invalid UserID or Password. Please try again."
        )

    # Render login page for GET requests
    return render_template("AdminLog.html")
    
#Admin Dashboard Route
@app.route('/AdminDash')
def AdminDash():
    try:
        registrations = Registration.query.all()  # Fetch all records
        return render_template("AdminDash.html", registrations=registrations)
    except Exception as e:
        logging.error(f"Error fetching registrations: {e}")
        return "Error loading dashboard", 500

@app.route("/delete_registration/<user_id>")
def delete_registration(user_id):
    try:
        app.logger.info(f"Delete route called for user_id: {user_id}")
        engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])
        metadata = MetaData()
        metadata.reflect(bind=engine)

        dropped_tables = set()  # To avoid double-dropping

        # Step 1: Drop tables that start with the exact prefix (case-sensitive)
        prefix = f"{user_id}_"
        for table_name in list(metadata.tables):
            if table_name.startswith(prefix):
                Table(table_name, metadata, autoload_with=engine).drop(engine)
                app.logger.info(f"Dropped table: {table_name}")
                dropped_tables.add(table_name.lower())

        # Step 2: Case-insensitive fallback for any missed tables
        for table_name in list(metadata.tables):
            if table_name.lower().startswith(user_id.lower() + "_") and table_name.lower() not in dropped_tables:
                Table(table_name, metadata, autoload_with=engine).drop(engine)
                app.logger.info(f"Dropped table (case-insensitive match): {table_name}")
                dropped_tables.add(table_name.lower())

        # Step 3: Drop <user_id>_customers table (case-insensitive match)
        customer_table_name = f"{user_id}_customers"
        for table_name in list(metadata.tables):
            if table_name.lower() == customer_table_name.lower() and table_name.lower() not in dropped_tables:
                Table(table_name, metadata, autoload_with=engine).drop(engine)
                app.logger.info(f"Dropped table: {table_name}")
                dropped_tables.add(table_name.lower())

        # Step 4: Delete from Registration table
        reg = Registration.query.filter_by(UserID=user_id).first()
        if reg:
            db.session.delete(reg)
            db.session.commit()
            flash("User and all associated tables deleted.", "success")
        else:
            flash("User not found in registration.", "error")

    except Exception as e:
        app.logger.error(f"Error deleting user: {e}")
        flash("An error occurred while deleting the user.", "error")

    return redirect(url_for("AdminDash"))

@app.route("/About.html")
def About():
    return render_template("About.html")

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Error occurred: {e}")
    return "An unexpected error occurred. Please try again.", 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    scheduler.start()  # ✅ Start it ONLY ONCE here
    atexit.register(lambda: scheduler.shutdown())  # Graceful shutdown on exit

    app.run(debug=True)
