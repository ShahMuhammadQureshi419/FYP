# InfectTest

## Abstract
The global market's reach of Android devices makes the system a prime target for cyber criminals. In 2023 mobile malware attacks were reported by Kaspersky at a staggering 33.8 million, with a year over year increase of 52%. The Android operating system sustained the impact of these attacks accounting for 92% and being the primary victim. Outdated cybersecurity tools, relying on signature-based checks, struggle to detect polymorphic malware that skillfully evades static analysis.

This paper proposes a solution based on hybrid malware detection that integrates both static and dynamic analysis with artificial intelligence. We utilize AndroPyTool to execute applications within a safeguarded sandbox partitioned environment extracting runtime opcodes, API calls and permission which are executed. These outputs are used as input into a Random Forest for Multi classification which may accurately identify and categorize variants of malware with there families which includes adwares, SMSware and ransomware.

## Installation

### Prerequisites
- Python 3.11 (installation instructions below)
- Linux-based system (recommended)

### Python 3.11 Installation
Run the following commands to install Python 3.11:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev \
libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev \
libgdbm-dev libdb5.3-dev libbz2-dev libexpat1-dev liblzma-dev \
tk-dev libffi-dev uuid-dev wget


cd /usr/src
sudo wget https://www.python.org/ftp/python/3.11.9/Python-3.11.9.tgz
sudo tar xzf Python-3.11.9.tgz
cd Python-3.11.9
sudo ./configure --enable-optimizations
sudo make -j$(nproc)
sudo make altinstall

# Verify installation
python3.11 --version



## Cmds

    chmod +x setup.sh
    
    ./setup.sh
    
