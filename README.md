# CipherLab Pro — Information Security Project
**BS Software Engineering | Information Security**

---

## Project Structure

```
cipherlab/
│
├── cipher_engine.py   ← Core cipher algorithms (XOR, Caesar, AES-256)
├── cli.py             ← Interactive console application
├── api_server.py      ← Flask REST API (connects Python to browser)
│
├── index.html         ← Web frontend (links to style.css + app.js)
├── style.css          ← All CSS styles
├── app.js             ← Frontend JavaScript (calls Python API)
│
└── README.md          ← This file
```

---

## How the Files Are Interlinked

```
cipher_engine.py
      ↑ imported by
  ┌───┴──────────────┐
cli.py           api_server.py
(console)        (Flask server)
                      ↑ fetches from
              ┌───────┴───────┐
           app.js ←── index.html
           (JS)       (HTML)
                         ↓ links
                      style.css
```

---

## Running the Project

### Option A — Console Only (Python, no browser needed)
```bash
python cli.py
```

### Option B — Web App with Python Backend (Recommended)
```bash
# Step 1 — Install dependencies
pip install flask pycryptodome

# Step 2 — Start the API server
python api_server.py

# Step 3 — Open browser
# Go to: http://localhost:5000
```

### Option C — Web App Standalone (no Python server)
Open `index.html` directly in your browser.
- XOR and Caesar ciphers work fully (JavaScript fallback)
- AES-256 requires the Python server (Option B)
- File encryption and image export always work

---

## API Endpoints (when api_server.py is running)

| Method | Endpoint              | Description          |
|--------|-----------------------|----------------------|
| GET    | `/`                   | Serves index.html    |
| GET    | `/api/status`         | Server health check  |
| POST   | `/api/xor/encrypt`    | XOR encrypt text     |
| POST   | `/api/xor/decrypt`    | XOR decrypt text     |
| POST   | `/api/caesar/encrypt` | Caesar encrypt text  |
| POST   | `/api/caesar/decrypt` | Caesar decrypt text  |
| POST   | `/api/aes/encrypt`    | AES-256-CBC encrypt  |
| POST   | `/api/aes/decrypt`    | AES-256-CBC decrypt  |

**Example API call:**
```bash
curl -X POST http://localhost:5000/api/xor/encrypt \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello", "key": "SecretKey"}'
```

---

## Algorithms Implemented

| Algorithm | Type        | Key Required | Security Level   |
|-----------|-------------|--------------|------------------|
| XOR       | Symmetric   | Yes          | Educational      |
| Caesar    | Substitution| No (shift)   | Historical only  |
| AES-256   | Symmetric   | Yes          | Industry-grade   |

---

## Dependencies

```
Python 3.8+
flask          (pip install flask)
pycryptodome   (pip install pycryptodome)   ← AES only
```
