# Password Strength Analyzer

A Flask-based software project that evaluates password strength, provides improvement suggestions, generates strong passwords, and optionally checks password reuse using password hashes.

## Features

- Password length analysis
- Uppercase/lowercase analysis
- Number and special-character checks
- Common-password detection
- Repeated-character detection
- Sequential-pattern detection
- Strength classification
- Suggestions for improving passwords
- Secure random password generator
- SQLite password-history module
- Password history stores SHA-256 hashes rather than plaintext passwords

## Run

1. Open this folder in VS Code.
2. Create a virtual environment:

   python -m venv venv

3. Activate it on Windows:

   venv\Scripts\activate

4. Install dependencies:

   pip install -r requirements.txt

5. Start the application:

   python app.py

6. Open:

   http://127.0.0.1:5000

## Note

For a production authentication system, use a dedicated password-hashing algorithm such as Argon2id, bcrypt, or scrypt with appropriate parameters rather than SHA-256 alone.
