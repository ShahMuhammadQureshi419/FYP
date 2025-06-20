
![Logo](https://github.com/user-attachments/assets/7065d725-ea8e-4342-ad87-b5cf14ec5ced)



# InfectTest

The global market's reach of Android devices makes the system a prime target for cyber criminals. In 2023 mobile malware attacks were reported by Kaspersky at a staggering 33.8 million, with a year over year increase of 52%. The Android operating system sustained the impact of these attacks accounting for 92% and being the primary victim. Outdated cybersecurity tools, relying on signature-based checks, struggle to detect polymorphic malware that skillfully evades static analysis.

This paper proposes a solution based on hybrid malware detection that integrates both static and dynamic analysis with artificial intelligence. We utilize AndroPyTool to execute applications within a safeguarded sandbox partitioned environment extracting runtime opcodes, API calls and permission which are executed. These outputs are used as input into a Random Forest for Multi classification which may accurately identify and categorize variants of malware with there families which includes adwares, SMSware and ransomware.


## Appendix

Any additional information goes here


## License

[MIT](https://choosealicense.com/licenses/mit/)


## Documentation

[Documentation](https://linktodocumentation)


## Authors

- [@Mehdi Badami](https://www.linkedin.com/in/mehdi-badami/)
- [@Shah Muhammad Qureshi](https://www.linkedin.com/in/smq8/)
- [@kashmala Hashmi](https://www.linkedin.com/in/kashmala-hashmi-744131231/)

## Installation


- Python 3.11 (installation instructions below)
- Linux-based system (recommended)

### setting up python3.11

 - Getting Dependecies for Linux

```bash
> sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev \
libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev \
libgdbm-dev libdb5.3-dev libbz2-dev libexpat1-dev liblzma-dev \
tk-dev libffi-dev uuid-dev wget
```

- getting python.11.9 

```bash
  cd /usr/src
sudo wget https://www.python.org/ftp/python/3.11.9/Python-3.11.9.tgz
sudo tar xzf Python-3.11.9.tgz
cd Python-3.11.9
sudo ./configure --enable-optimizations
sudo make -j$(nproc)
sudo make altinstall
```


- verify the installation
```bash
 > python3.11 --version
```
- run setup.sh script for downloading more dependencies

```bash
# Make setup script executable
> chmod +x setup.sh

# Run setup script
> sudo ./setup.sh
```

