# 🔐 Password Strength Analyzer

Password Strength Analyzer is a simple web application that helps users understand how secure their passwords are. The application checks a password based on its length, use of uppercase and lowercase letters, numbers, special characters, repeated characters, and common password patterns.

It gives the user a clear strength level and explains what can be improved. The project also includes a password generator that creates strong random passwords.

An additional password history feature is included using SQLite to check whether a password has been used before. Instead of storing the actual password, the system stores a hashed version for the history check.

### Features

* Password strength analysis
* Strength score and classification
* Checks password length and complexity
* Detects common and predictable passwords
* Detects repeated characters and sequences
* Provides suggestions to improve weak passwords
* Generates strong random passwords
* Checks password reuse
* Stores password history using hashes
* Simple and responsive web interface

### Technologies Used

**Python | Flask | HTML | CSS | JavaScript | SQLite**

### What I Learned

Through this project, I gained practical experience in building a web application with Flask, working with databases, handling user input, applying password security concepts, and creating an interactive frontend.

### Future Improvements

The project can be extended with advanced password pattern detection, entropy analysis, larger common-password datasets, and stronger password-hashing methods such as Argon2id or bcrypt.

**Project Type:** Web Application / Cybersecurity Project
