from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import json

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    certificate = db.Column(db.Text, nullable=True)  # New column for storing certificates

# Generate keys for a user
def generate_keys():
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    )

# Generate a certificate for a user
def generate_certificate(user, issuer_private_key):
    # Certificate data
    certificate_data = {
        "username": user.username,
        "public_key": user.public_key,
        "issuer": "Certificate Authority",  # In this case, self-signed certificates
        "valid_from": "2025-01-01",
        "valid_to": "2026-01-01"
    }

    # Convert certificate data to JSON string
    certificate_json = json.dumps(certificate_data)

    # Sign the certificate data with the issuer's private key
    signature = issuer_private_key.sign(certificate_json.encode(), hashes.SHA256())

    # Return the certificate as a dictionary
    return {
        "data": certificate_data,
        "signature": signature.hex()  # Store the signature as a hex string
    }

# Routes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")

        # Register User
        if action == "register":
            username = request.form.get("username")
            if not username:
                flash(" Username cannot be empty.")
                return redirect(url_for("index"))
            if User.query.filter_by(username=username).first():
                flash(" Username already exists.")
                return redirect(url_for("index"))

            private_key_pem, public_key_pem = generate_keys()
            new_user = User(username=username, private_key=private_key_pem, public_key=public_key_pem)
            db.session.add(new_user)
            db.session.commit()

            flash(f" User '{username}' registered successfully.")
            return redirect(url_for("index"))

        # Send Message
        elif action == "send":
            sender = request.form.get("sender")
            recipient = request.form.get("recipient")
            message = request.form.get("message")

            sender_user = User.query.filter_by(username=sender).first()
            recipient_user = User.query.filter_by(username=recipient).first()

            if not sender_user or not recipient_user:
                flash(" Sender or recipient does not exist.")
                return redirect(url_for("index"))
            if not message:
                flash(" Message cannot be empty.")
                return redirect(url_for("index"))

            # Load sender's private key
            private_key = serialization.load_pem_private_key(sender_user.private_key.encode(), password=None)

            # Sign the message
            signature = private_key.sign(message.encode(), hashes.SHA256())
            signature_hex = signature.hex()

            session["signed_message"] = message
            session["signature_hex"] = signature_hex
            session["current_sender"] = sender
            session["current_recipient"] = recipient

            flash(f" Message sent from '{sender}' to '{recipient}'.")
            flash(f" Signature (hex): {signature_hex[:100]}...")
            return redirect(url_for("index"))

        # Verify Signature
        elif action == "verify":
            if "signed_message" not in session or "signature_hex" not in session:
                flash(" Please send a message first.")
                return redirect(url_for("index"))

            current_message = request.form.get("message")  # Get the current message from the form
            sender_username = session["current_sender"]
            sender_user = User.query.filter_by(username=sender_username).first()

            if not sender_user:
                flash(" Sender does not exist.")
                return redirect(url_for("index"))

            # Load sender's public key
            public_key = serialization.load_pem_public_key(sender_user.public_key.encode())

            # Convert signature from hex to bytes
            signature = bytes.fromhex(session["signature_hex"])

            try:
                public_key.verify(signature, current_message.encode(), hashes.SHA256())
                flash(f" Signature Verified:  VALID (From: {session['current_sender']}, To: {session['current_recipient']})")
                flash(f" Original Message: {session['signed_message']}")
            except InvalidSignature:
                flash(f" Signature Verified:  INVALID (From: {session['current_sender']}, To: {session['current_recipient']})")
                flash("⚠️ The message has been tampered with or does not match the original.")

            return redirect(url_for("index"))

        # Exit and Clear Session
        elif action == "exit":
            session.clear()  # Clear all session data
            flash(" Session cleared. You can start fresh!")
            return redirect(url_for("index"))
    
    '''users = User.query.all()
    return render_template("index.html", users=users)'''

    users = User.query.all()
    selected_sender = session.get("current_sender", "")
    selected_recipient = session.get("current_recipient", "")
    return render_template("index.html", users=users, selected_sender=selected_sender, selected_recipient=selected_recipient)


@app.route("/generate_certificate/<username>", methods=["GET"])
def generate_certificate_route(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(" User does not exist.")
        return redirect(url_for("index"))

    # Load the user's private key to sign the certificate
    private_key = serialization.load_pem_private_key(user.private_key.encode(), password=None)

    # Generate the certificate
    certificate = generate_certificate(user, private_key)

    # Save the certificate in the database
    user.certificate = json.dumps(certificate)
    db.session.commit()

    flash(f" Certificate generated for user '{username}'.")
    return redirect(url_for("index"))

@app.route("/view_certificate/<username>", methods=["GET"])
def view_certificate_route(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.certificate:
        flash(" Certificate not found for this user.")
        return redirect(url_for("index"))

    # Parse the certificate from JSON
    certificate = json.loads(user.certificate)

    return render_template("view_certificate.html", username=username, certificate=certificate)

@app.route("/verify_certificate/<username>", methods=["GET"])
def verify_certificate_route(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.certificate:
        flash(" Certificate not found for this user.")
        return redirect(url_for("index"))

    # Parse the certificate from JSON
    certificate = json.loads(user.certificate)

    # Extract certificate data and signature
    certificate_data = json.dumps(certificate["data"])
    signature = bytes.fromhex(certificate["signature"])

    # Load the user's public key
    public_key = serialization.load_pem_public_key(user.public_key.encode())

    try:
        # Verify the certificate's signature
        public_key.verify(signature, certificate_data.encode(), hashes.SHA256())
        flash(f" Certificate verified successfully for user '{username}'.")
    except InvalidSignature:
        flash(f" Certificate verification failed for user '{username}'. It may have been tampered with.")

    return redirect(url_for("index"))
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
