# SecureAuthX

**SecureAuthX** is a lightweight Python authentication helper designed for learning, demos, and small projects.  
It provides secure password hashing, credential verification, and time-limited token-based authentication — all in a **single Python file** with **no external dependencies**.

---

## Features

-  Secure password hashing using **PBKDF2-HMAC-SHA256**
-  Constant-time password comparison to prevent timing attacks
-  HMAC-signed, time-limited authentication tokens
-  Optional persistent **JSON-based user store**
-  Simple API, easy to extend
-  Includes a CLI demo

---

## Project Structure

```
SecureAuthX/
│
├── secureauthx.py   # Core authentication logic
└── README.md        # Project documentation
```

---

## Installation

No installation required.

Just download the file:

```bash
git clone https://github.com/your-username/SecureAuthX.git
cd SecureAuthX
```

> Requires **Python 3.8+**

---

## Basic Usage

### Import and Initialize

```python
from secureauthx import SecureAuthX

auth = SecureAuthX(store_path="users.json")
```

---

### Add a User

```python
auth.add_user("alice", "securePassword123")
```

---

### Authenticate a User

```python
token = auth.authenticate_user("alice", "securePassword123")
print(token)
```

---

### Verify a Token

```python
payload = auth.verify_token(token)
print(payload)
```

 Returns user data if valid  
 Returns `None` if invalid or expired

---

## Token Format

Tokens are **URL-safe** and contain:
- Username
- Expiry timestamp
- HMAC-SHA256 signature

```
base64url(payload).base64url(signature)
```

---

## CLI Demo

Run the module directly:

```bash
python secureauthx.py
```

This demo will:
- Create a user
- Authenticate the user
- Generate a token
- Verify token expiry

---

## Security Notes

- Passwords are never stored in plaintext
- Uses industry-standard hashing (PBKDF2)
- Resistant to timing attacks
- Designed for **educational & small-scale use**
- Not a replacement for full auth frameworks in production

---

## Future Enhancements

- JWT support
- Email & password policy validation
- Rate limiting & brute-force protection
- Flask / FastAPI integration
- Database-backed user store (SQLite)

---

## License

MIT License — feel free to use, modify, and distribute.

---

##  Author

Built as part of the **SecureAuthX** project  
Focused on learning secure authentication fundamentals.
