# CyberShield Developer & Setup Guide

## 1. System Requirements
- **Python**: 3.10+ (Tested on Python 3.13)
- **Node.js**: 18+ (Tested on Node.js v24)
- **Operating Systems**: Linux (Ubuntu/Debian, Fedora), macOS, Windows 10/11
- **Optional Tools**: `clamscan` (ClamAV), `suricata`, Rust toolchain (`cargo`)

## 2. Quick Start

### Step 1: Clone and Set Up Virtual Environment
```bash
git clone https://github.com/your-org/cybershield.git
cd cybershield

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt
```

### Step 2: Initialize Database
```bash
python -c "from backend.app.db.base import Base; from backend.app.models import *; from backend.app.db.session import engine; Base.metadata.create_all(bind=engine); print('Initialized 21 database tables!')"
```

### Step 3: Run the Backend API
```bash
# Launch FastAPI server on port 8000
python -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```
API Documentation will be available at `http://localhost:8000/docs`.

### Step 4: Run the Web Dashboard
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```
The CyberShield Dashboard will launch at `http://localhost:5173`.

### Step 5: Run Automated Tests
```bash
pytest backend/tests -v
```

## 3. Building Cross-Platform Agents

### Linux Agent (Rust)
```bash
cd agents/linux
cargo build --release
./target/release/cybershield-agent-linux status
./target/release/cybershield-agent-linux scan /path/to/folder
```

### Browser Extension (Manifest V3)
1. Open Google Chrome or Microsoft Edge.
2. Navigate to `chrome://extensions`.
3. Enable **Developer Mode**.
4. Click **Load unpacked** and select `agents/browser-extension/`.

### Android Agent
Android agent source code is located in `agents/android/`. Open in Android Studio and assemble with `./gradlew assembleDebug`.
