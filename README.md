# Digital Signature Scheme

## 📽️ Live Demo

🎥 [Watch the Project Demo](https://drive.google.com/file/d/15Cj42SxYErl3ZmxI-hC1qAtBhQUlpDGb/view?usp=sharing)


## Project Overview
This project implements a **Digital Signature Scheme** using the Digital Signature Standard (DSS) for secure data authentication. The system is built using Python and Flask, and it demonstrates how users can generate, sign, and verify messages and certificates securely.

## Features
- **User Registration:** Generate DSA key pairs for new users.
- **Message Signing:** Sign messages with a user's private key.
- **Signature Verification:** Verify message authenticity using the sender's public key.
- **Certificate Generation:** Generate a certificate for a user signed by their own private key.
- **Certificate Viewing & Verification:** View and verify self-signed digital certificates.
- **Tampering Detection:** Alert when a message is altered.
- **Session Management:** Clear session for a fresh start.

### Simple Explanation
A digital signature is like an electronic fingerprint. It ensures the authenticity and integrity of a message.

#### Example:
1. Alice registers and gets a private and public key.
2. She writes "Hello Bob" and signs it using her private key.
3. Bob receives the message and the signature.
4. Bob verifies the signature using Alice's public key.
5. If the signature is valid, he knows the message came from Alice and wasn't changed.

## Prerequisites
Make sure you have the following installed:
- Python 3.7+
- pip

---

## Libraries Used

| Library         | Purpose                                      |
|----------------|----------------------------------------------|
| Flask           | Web framework for Python                     |
| Flask_SQLAlchemy| ORM for SQLite database                      |
| Cryptography    | DSA key generation, signing, and verification |
| JSON            | Used for certificate formatting              |


## Code Structure
```
DSS_Project/

│
├── app.py                          # Main Flask application
├── users.db                        # SQLite database (auto-created by SQLAlchemy)
│
├──  templates/                   # HTML templates
│   ├── index.html                 # Main interface for DSS
│   └── view_certificate.html      # Certificate view page
│
├──  static/                      # Static files like CSS/images
│   ├── styles.css                # Custom styling
│   └── pup.avif                  # Background image
│
├──  requirements.txt             # List of Python packages to install

```

Install all dependencies using:
```bash
pip install -r requirements.txt
```

---

## How to Run the Project
### 1. Clone the Repository
```bash
git clone <repo-url>
cd digital-signature-scheme
```
### 2. **Set up environment:** Ensure Python and pip are installed.

###3. **Install dependencies:**
```bash
pip install flask flask_sqlalchemy cryptography
```

### 4. Create the SQLite Database
```bash
python app.py
```

### 3. Launch the Flask App
```bash
python app.py
```

### 4. Open in Browser
Go to: [http://127.0.0.1:5000](http://127.0.0.1:5000)


---


### Google Colab
You can also run this project using Google Colab: [Google Colab Link](https://colab.research.google.com/drive/1qvsRfLlnSTD4EO1_XSN6c8PH6Ojy5Foh?usp=sharing)



## Output
- **Registered Users List** with certificate generation and verification links.
- **User Registration Form** to create new users.
- **Message Sending Form** where users sign and send messages.
- **Tampering Detection** alert if the message has been modified.
- **Certificate Viewer** to show certificate contents.

## Code Summary (In Simple Words)
1. **Key Generation:** Users get a private and public DSA key.
2. **Signing a Message:** Sender uses private key to create a signature for the message.
3. **Verification:** Receiver uses sender's public key to verify the signature and ensure the message was not altered.
4. **Certificates:** Self-signed certificates ensure the public key belongs to a specific user.
5. **Database:** Uses SQLite to store user info and certificates.
6. **HTML Pages:** User-friendly web interface using Flask templates.

### Example:
- **Register User:** Create "Alice" with a unique DSA key pair.
- **Send Message:** Alice sends "Hello Bob" signed with her key.
- **Verify Message:** Bob verifies the signature to check it's from Alice and unchanged.


## Real-Time Use Cases
- **E-Government:** Signing official digital documents.
- **Banking Applications:** Secure transaction messages.
- **Email Security:** Signing emails to prevent tampering.
- **Blockchain:** Verifying identity and transactions.

## Future Enhancements
- **Role-Based Access Control:** Different permissions for users/admins.
- **Third-Party Certificate Authority Integration:** Instead of self-signed certs.
- **Public Certificate Directory:** Search and verify user certs.
- **Enhanced UI/UX:** Use React or Vue for a modern frontend.
- **Token-based Authentication:** For API and mobile use.

## Contribution

Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to create a pull request or open an issue on GitHub.

## Author


GitHub: [@rithikashettigar](https://github.com/rithikashettigar)\
Email: [rithikauj@gmail.com@gmail.com](mailto\:rithikauj@gmail.com)

Thank you for visiting ❤️



---

