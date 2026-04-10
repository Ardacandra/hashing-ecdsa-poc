# hashing-ecdsa-poc

Local web and mobile proof-of-concept apps demonstrating SHA-256 hashing and ECDSA P-256 signing/verification.

---

## Repository Structure

```
hashing-ecdsa-poc/
├── specs/
│   ├── requirements.md       — functional requirements and acceptance criteria
│   ├── tech-spec.md          — architecture, key flows, error handling, security
│   └── verification.md       — test vectors and verification steps
├── app/
│   └── web/                  — Assignment 1: static web app
│       ├── index.html        — UI (two tabs: SHA-256 and ECDSA P-256)
│       ├── style.css         — styles
│       ├── crypto-utils.js   — pure async crypto functions (also used by tests)
│       ├── app.js            — UI event handlers
│       ├── package.json      — Jest test runner config
│       └── tests/
│           ├── setup.js              — Jest setup (Web Crypto global for Node.js 18+)
│           └── crypto-utils.test.js  — automated test suite
└── README.md
```

---

## Assignment 1 — Web App (SHA-256 + ECDSA P-256)

### Prerequisites

The web app runs entirely in the browser using the built-in [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

**Required:**
- A modern browser — Chrome 37+, Firefox 34+, or Edge 12+. Any current browser on Ubuntu qualifies.

**Required (pick one) — local file server:**

| Option | Install command |
|--------|----------------|
| Python 3 | Pre-installed on Ubuntu 20.04+. Verify: `python3 --version` |
| Node.js + npx | `sudo apt update && sudo apt install -y nodejs npm` |

> **Why a server instead of `file://`?**
> The Web Crypto API requires a secure context. `localhost` counts as secure; opening `index.html` directly via `file://` may block `crypto.subtle` in some browsers.

### Environment Setup (Ubuntu)

```bash
# 1. Clone the repository (if you haven't already)
git clone https://github.com/Ardacandra/hashing-ecdsa-poc.git
cd hashing-ecdsa-poc

# 2. Verify Python 3 is available (recommended — no extra install needed)
python3 --version
# Expected: Python 3.x.x

# 3. (Alternative) Install Node.js if you prefer npx serve
sudo apt update && sudo apt install -y nodejs npm
node --version   # Expected: v18+ recommended
npm --version
```

### Running the App

**Option A — Python 3 (recommended, zero extra dependencies):**

```bash
cd app/web
python3 -m http.server 8080
```

Then open your browser and go to: `http://localhost:8080`

**Option B — Node.js / npx serve:**

```bash
cd app/web
npx serve .
```

Then open your browser and go to the URL printed in the terminal (typically `http://localhost:3000`).

### Using the UI

The app has two sections on a single page:

#### SHA-256 Hashing
1. Type any text into the **Message** field under the SHA-256 section.
2. Click **Hash**.
3. The 64-character lowercase hex digest appears in the output field.

#### ECDSA P-256
1. Click **Generate Keypair** — the public key (130 hex chars) and private key scalar (64 hex chars) appear.
2. Type a message in the **Message** field and click **Sign**.
   - The 128-character hex signature (`r || s`) appears.
   - The message is automatically copied to the Verify section.
3. Click **Verify** to confirm the signature against the message and public key.
   - Result displays **VALID** (green) or **INVALID** (red).
   - Edit the message or signature before verifying to observe the INVALID path.

### Stopping the Server

Press `Ctrl+C` in the terminal running the server.

### Running the Automated Tests

The test suite uses Jest and requires **Node.js 18+**.

```bash
cd app/web

# Install Jest (first run only)
npm install

# Run all tests
npm test
```

Expected output: 16 tests across 4 suites, all passing. Tests cover:
- SHA-256 known NIST vectors (V-H1 through V-H4)
- Keypair format checks (public key 130 chars, private key 64 chars)
- Sign + verify round-trips (RT-1 through RT-4)
- Guard and validation error messages (GV-1 through GV-6)

---

## Specs

Full technical details are in the [specs/](specs/) directory:

- [Requirements](specs/requirements.md)
- [Technical Specification](specs/tech-spec.md)
- [Verification](specs/verification.md)