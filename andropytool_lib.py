import os
import subprocess

class AndroPyToolClient:
    def __init__(self, vt_key_path=None, enable_all=False, enable_dynamic=True, enable_virustotal=True):
        self.enable_all = enable_all
        self.enable_dynamic = enable_dynamic
        self.enable_virustotal = enable_virustotal
        self.vt_key_path = vt_key_path
        self.docker_image = "alexmyg/andropytool"
        self.docker_apk_mount = "/apks"

    def run_analysis(self, apk_path, output_dir):
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        # Convert to absolute paths
        abs_apk_path = os.path.abspath(apk_path)
        apk_dir = os.path.dirname(abs_apk_path)
        apk_filename = os.path.basename(abs_apk_path)
        docker_source = self.docker_apk_mount + "/"

        # Create output directory if needed
        os.makedirs(output_dir, exist_ok=True)

        # Load VirusTotal key
        vt_key = None
        if self.enable_virustotal:
            if not self.vt_key_path or not os.path.isfile(self.vt_key_path):
                raise FileNotFoundError(f"VirusTotal key file not found: {self.vt_key_path}")
            with open(self.vt_key_path, 'r') as f:
                vt_key = f.read().strip()
            if not vt_key:
                raise ValueError("VirusTotal key file is empty.")

        # Construct Docker command using absolute path
        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{apk_dir}:{self.docker_apk_mount}',  # host absolute path : container path
            self.docker_image,
            '-s', docker_source
        ]

        if self.enable_all:
            cmd.append('--all')
        if self.enable_dynamic:
            cmd.append('-dr')
        if self.enable_virustotal:
            cmd.extend(['-vt', vt_key])

        cmd.extend(['--single', '--color'])

        try:
            print(f"[+] Running AndroPyTool:\n{' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            print(f"[✓] Analysis completed: {apk_filename}")
            return True
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"AndroPyTool failed: {e}")
        except FileNotFoundError:
            raise EnvironmentError("Docker is not installed or not found in PATH")
