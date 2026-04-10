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
│   ├── web/                  — Assignment 1: static web app
│   │   ├── index.html        — UI (two tabs: SHA-256 and ECDSA P-256)
│   │   ├── style.css         — styles
│   │   ├── crypto-utils.js   — pure async crypto functions (also used by tests)
│   │   ├── app.js            — UI event handlers
│   │   ├── package.json      — Jest test runner config
│   │   └── tests/
│   │       ├── setup.js              — Jest setup (Web Crypto global for Node.js 18+)
│   │       └── crypto-utils.test.js  — automated test suite
│   └── mobile/               — Assignment 2: Flutter Android app
│       ├── lib/
│       │   ├── main.dart             — MaterialApp entry point
│       │   ├── screens/
│       │   │   └── home_screen.dart  — two-tab UI (SHA-256 and ECDSA P-256)
│       │   └── crypto/
│       │       ├── sha256_service.dart  — SHA-256 wrapper (pointycastle)
│       │       └── ecdsa_service.dart   — P-256 keygen, sign, verify (pointycastle)
│       ├── test/
│       │   └── crypto_test.dart      — flutter test suite
│       └── pubspec.yaml
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

---

## Assignment 2 — Mobile App (SHA-256 + ECDSA P-256)

Targets an Android emulator (API 33, Pixel 4 profile). Uses Flutter with the `pointycastle` library for all crypto.

### Prerequisites

| Tool | Required version | Purpose |
|------|-----------------|---------|
| OpenJDK | 17 | Required by Android Gradle Plugin 8.x |
| Android SDK | compileSdk 36, platform-tools | Build and emulator toolchain |
| Android Emulator image | API 33, x86_64 | `google_apis;x86_64` system image |
| Flutter | 3.41.6 stable | App framework and `flutter test` runner |

### Environment Setup (Ubuntu)

#### Step 1 — Java 17

```bash
sudo apt update
sudo apt install -y openjdk-17-jdk

java -version
# Expected: openjdk version "17.x.x ..."

# If multiple Java versions exist, select 17:
sudo update-alternatives --config java
```

Set `JAVA_HOME` in your shell profile (`~/.bashrc` or `~/.zshrc`):

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
```

#### Step 2 — Android Command-Line Tools

Download the **Command line tools only** package for Linux from
`https://developer.android.com/studio` (scroll to "Command line tools only").

Then unpack it into the required directory layout:

```bash
mkdir -p ~/Android/sdk/cmdline-tools/latest
unzip cmdline-tools-linux.zip -d /tmp/cmdtools
mv /tmp/cmdtools/cmdline-tools/* ~/Android/sdk/cmdline-tools/latest/
```

Add the following to your shell profile and reload it:

```bash
export ANDROID_HOME=$HOME/Android/sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
export PATH=$PATH:$ANDROID_HOME/platform-tools
export PATH=$PATH:$ANDROID_HOME/emulator
```

Verify the variables are active:

```bash
echo $ANDROID_HOME
# Expected: /home/<you>/Android/sdk

sdkmanager --version
# Expected: a version number, e.g. 12.0
```

#### Step 3 — Android SDK Components

```bash
# Accept all SDK licences
sdkmanager --licenses

# Install the required components
sdkmanager \
  "platform-tools" \
  "build-tools;36.0.0" \
  "platforms;android-33" \
  "platforms;android-36" \
  "system-images;android-33;google_apis;x86_64" \
  "emulator"
```

#### Step 4 — Create the Android Virtual Device (AVD)

```bash
avdmanager create avd \
  --name Pixel4_API33 \
  --package "system-images;android-33;google_apis;x86_64" \
  --device "pixel_4"
```

Verify it was created:

```bash
avdmanager list avd
# Should list: Pixel4_API33
```

#### Step 5 — Flutter (stable channel)

The spec was written against 3.24.0, but any current stable release works — Flutter is backward-compatible and `pointycastle` is maintained for all stable versions.

**Option A — snap (easiest on Ubuntu):**

```bash
sudo snap install flutter --classic
flutter channel stable
flutter upgrade

flutter --version
# Note the actual Flutter and Dart versions for your records
```

**Option B — manual install:**

Download the latest stable Linux SDK archive from `https://docs.flutter.dev/get-started/install/linux`,
extract it, and add the `flutter/bin` directory to your `PATH`.

#### Step 6 — Accept Android Licences in Flutter

```bash
flutter doctor --android-licenses
# Press 'y' to accept each licence
```

#### Step 7 — Verify the Full Setup

```bash
flutter doctor
```

All relevant items should be green. A warning about Android Studio is expected and harmless — the command-line tools are sufficient.

### Running the Emulator

```bash
# Launch the emulator in the background
emulator -avd Pixel4_API33 &

# Wait ~30–60 s for it to boot, then confirm Flutter sees it:
flutter devices
# Expected: a line showing "sdk gphone x86 64 (mobile)"
```

### Running the App

```bash
cd app/mobile
flutter pub get   # download dependencies (first run only)
flutter run       # builds and deploys to the running emulator
```

### Running the Automated Tests

Tests run on the host machine (no emulator required):

```bash
cd app/mobile
flutter test
```

### Using the UI

The app is a single screen with two tabs:

#### SHA-256 tab
1. Type any text in the input field.
2. Tap **Hash**.
3. The 64-character lowercase hex digest appears below.

#### ECDSA P-256 tab
1. Tap **Generate Keypair** — the public key (130 hex chars) and private key scalar (64 hex chars) appear.
2. Enter a message and tap **Sign** — the 128-character hex signature (`r || s`) appears, and the message is auto-copied to the verify field.
3. Tap **Verify** — result shows **VALID** or **INVALID**.
   - Edit the message or signature before verifying to observe the INVALID path.

---

## Specs

Full technical details are in the [specs/](specs/) directory:

- [Requirements](specs/requirements.md)
- [Technical Specification](specs/tech-spec.md)
- [Verification](specs/verification.md)