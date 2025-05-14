#!/bin/bash

echo "[+] Starting InfectTest setup..."
echo "[+] Long live open source!"

# Step 1: Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "[!] Docker is not installed. Please install Docker and try again."
    exit 1
fi

# Step 2: Check if MobSF image exists locally
if [[ "$(docker images -q opensecurity/mobile-security-framework-mobsf:latest 2> /dev/null)" == "" ]]; then
    echo "[+] MobSF image not found locally. Pulling from Docker Hub..."
    docker pull opensecurity/mobile-security-framework-mobsf:latest
else
    echo "[+] MobSF Docker image already available locally."
fi

# Step 2.5: Check if AndroPyTool image exists locally
if [[ "$(docker images -q alexmyg/andropytool:latest 2> /dev/null)" == "" ]]; then
    echo "[+] AndroPyTool image not found locally. Pulling from Docker Hub..."
    docker pull alexmyg/andropytool:latest
else
    echo "[+] AndroPyTool Docker image already available locally."
fi

# Step 3: Start MobSF container (if not already running)
if [ "$(docker ps -q -f name=mobsf)" ]; then
    echo "[+] MobSF container is already running."
elif [ "$(docker ps -aq -f status=exited -f name=mobsf)" ]; then
    echo "[+] Starting existing stopped MobSF container..."
    docker start mobsf 
else
    echo "[+] Launching new MobSF container..."
    docker run -d --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
fi

# Step 4: Use Python 3.11 if available
PYTHON_BIN=$(command -v python3.11 || command -v python3)

if [ -z "$PYTHON_BIN" ]; then
    echo "[!] Python 3.11 is not installed. Please install it first."
    exit 1
fi

echo "[+] Using Python interpreter: $PYTHON_BIN"

# Step 5: Create virtual environment if not already present
VENV_DIR="InfectTest-env"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating Python virtual environment: $VENV_DIR"
    $PYTHON_BIN -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "[!] Failed to create virtual environment."
        exit 1
    fi
else
    echo "[+] Virtual environment already exists: $VENV_DIR"
fi

# Step 6: Activate virtual environment
echo "[+] Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Step 7: Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[!] Failed to install Python dependencies."
    deactivate
    exit 1
fi

# Step 8: Run the main application
echo "[+] Launching InfectTest..."
export XGBOOST_VERBOSITY=0
python main.py

# Done
echo "[+] InfectTest setup complete. MobSF is running at http://localhost:8000"
echo "[+] Default MobSF credentials: mobsf / mobsf"
