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

# Step 4: Use Python 3.11 forcefully
PYTHON_BIN=$(command -v python3.11)
echo "[+] Using Python interpreter: $PYTHON_BIN"

# Step 5: Create virtual environment if not already present
if [ ! -d "InfectTest-env" ]; then
    echo "[+] Creating Python virtual environment: InfectTest-env"
    $PYTHON_BIN -m venv InfectTest-env
else
    echo "[+] Virtual environment already exists: InfectTest-env"
fi

# Activate virtual environment
source InfectTest-env/bin/activate

# Step 6: Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[!] Failed to install Python dependencies."
    deactivate
    exit 1
fi

# Step 7: Run the main application
echo "[+] Launching InfectTest..."
$PYTHON_BIN main.py

# Done
echo "[+] InfectTest setup complete. MobSF is running at http://localhost:8000"
echo "[+] Default MobSF credentials: mobsf / mobsf"
