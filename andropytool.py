#!/usr/bin/env python3
# this is the working of the andropytool on a single working apk its purpose was does python is able to run the docker with specific requirements or not 
# i have already mentioned the nessary change make yourself comfortable


import os
import sys
import subprocess

def main():
    # Hardcoded configuration  
    # jarvis take the file path from the main 
    APK_FILE = "/home/kali/Desktop/Uni_Stuff/FYP/App_code/main_mehdi_implementation/sample_apks/bf781f7d66a8ced4929674ea81a87c814f617ef677301b5ee4b4d32c04287b68.apk"
    ENABLE_ALL_STEPS = False          # Set to False to run only specific steps
    ENABLE_DYNAMIC_ANALYSIS = True  # Requires -dr flag
    ENABLE_VIRUSTOTAL = True        # Requires -vt flag
    VT_KEY_FILE = "/home/kali/Desktop/Uni_Stuff/FYP/App_code/main_mehdi_implementation/VTkey.txt"
    OUTPUT_DIR = "/home/kali/Desktop/Uni_Stuff/FYP/App_code/main_mehdi_implementation/reports" # change the output directory to uploads/{filename}{completetimestamp}
    APK_DIR = os.path.dirname(APK_FILE)
    APK_FILENAME = os.path.basename(APK_FILE)

    # Docker configuration
    DOCKER_IMAGE = "alexmyg/andropytool"
    DOCKER_APK_MOUNT = "/apks"  # As per documentation
    DOCKER_SOURCE = f"{DOCKER_APK_MOUNT}/"

    # Check if APK file exists
    if not os.path.isfile(APK_FILE):
        print(f"Error: APK file not found: {APK_FILE}")
        sys.exit(1)

    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Get VirusTotal API key if needed
    vt_key = None
    if ENABLE_VIRUSTOTAL:
        try:
            with open(VT_KEY_FILE, 'r') as f:
                vt_key = f.read().strip()
            if not vt_key:
                print(f"Error: VirusTotal API key not found in {VT_KEY_FILE}")
                sys.exit(1)
        except FileNotFoundError:
            print(f"Error: {VT_KEY_FILE} not found - please create it with your VirusTotal API key")
            sys.exit(1)

    # Build Docker command according to documentation
    cmd = [
        'docker', 'run', '--rm',
        '-v', f'{APK_DIR}:{DOCKER_APK_MOUNT}',
        '-v', f'{OUTPUT_DIR}:/home/andropytool/reports',  # Default output in container
        DOCKER_IMAGE,
        '-s', DOCKER_SOURCE  # As per documentation requirement
    ]

    # Add all steps if enabled
    if ENABLE_ALL_STEPS:
        cmd.append('--all')

    # Add dynamic analysis if enabled
    if ENABLE_DYNAMIC_ANALYSIS:
        cmd.append('-dr')

    # Add VirusTotal if enabled
    if ENABLE_VIRUSTOTAL:
        cmd.extend(['-vt', vt_key])

    # Add additional recommended flags
    cmd.extend([
                        # Filter valid and invalid APKs
        '--single',     # Save single analysis separately
        '--color'       # Enable colored output
    ])

    # Run AndroPyTool in Docker
    try:
        print(f"Starting analysis with command:\n{' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"\nAnalysis completed successfully!")
        print(f"APK analyzed: {APK_FILENAME}")
        print(f"Reports saved to: {OUTPUT_DIR}")
    except subprocess.CalledProcessError as e:
        print(f"\nError during analysis: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("\nError: docker not found. Please ensure Docker is installed and running.")
        sys.exit(1)

if __name__ == '__main__':
    main()
