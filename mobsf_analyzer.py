# mobsf_analyzer.py


import subprocess
import os
import json
from flask import jsonify

class MobSFClient:
    # the default constructor

    @staticmethod
    def just_opening_file(file_path, mode):
        
        with open(file_path, mode, encoding='utf-8') as file:
            return file.read()


    def __init__(self):
        self.MOBSF_URL = "http://localhost:8000"  # MobSF instance URL
        self.API_KEY = self.just_opening_file('config/mobsf_api_key.txt', 'r').strip()                # my API key
        self.UPLOAD_FOLDER = 'uploads'      # uploads_apk_folder
        os.makedirs(self.UPLOAD_FOLDER, exist_ok=True)


    # directive to run curl command as a subprocess
    def _run_curl(self, command):
        try:
            result = subprocess.run(command, capture_output=True, text=True)
#                                       ^ here all the curl commands would run from upload_file to pdf_generator

            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception as e:
            print(f"Error executing curl: {e}")
            return None

    def upload_file(self, file_path):
        
        """Upload file to MobSF and return hash"""

        curl_command = [
            'curl', '-F', f'file=@{file_path}',
            f'{self.MOBSF_URL}/api/v1/upload',
            '-H', f'Authorization: {self.API_KEY}'
        ]
        
        response = self._run_curl(curl_command)
        if response:
            return json.loads(response)
        return None

    def scan_file(self, file_hash):
        
        """Start static analysis scan"""
        
        curl_command = [
            'curl', '-X', 'POST', '--url', f'{self.MOBSF_URL}/api/v1/scan',
            '--data', f'hash={file_hash}',
            '-H', f'Authorization: {self.API_KEY}'
        ]
        
        return self._run_curl(curl_command)

    def generate_pdf_report(self, file_hash, output_path):
        
        """Generate and save PDF report"""
        
        curl_command = [
            'curl', '-X', 'POST', '--url', f'{self.MOBSF_URL}/api/v1/download_pdf',
            '--data', f'hash={file_hash}',
            '-H', f'Authorization: {self.API_KEY}',
            '--output', output_path
        ]
        return self._run_curl(curl_command) is not None

    def generate_json_report(self, file_hash, output_path):
        
        """Generate and save JSON report"""
        
        curl_command = [
            'curl', '-X', 'POST', '--url', f'{self.MOBSF_URL}/api/v1/report_json',
            '--data', f'hash={file_hash}',
            '-H', f'Authorization: {self.API_KEY}',
            '--output', output_path
        ]
        
        return self._run_curl(curl_command) is not None

    def analyze_apk(self, file_path):
        
        """Complete analysis workflow"""
        
        # Upload file
        upload_data = self.upload_file(file_path)
        if not upload_data:
            return None

        file_hash = upload_data.get('hash')
        file_name = upload_data.get('file_name', '').split('.')[0]
        
        # Start scan (we don't need the response for our workflow)
        self.scan_file(file_hash)
        
        # Generate reports
        pdf_path = os.path.join(self.UPLOAD_FOLDER, f'{file_name}_report.pdf')
        json_path = os.path.join(self.UPLOAD_FOLDER, f'{file_name}_report.json')
        
        self.generate_pdf_report(file_hash, pdf_path)
        self.generate_json_report(file_hash, json_path)
        
        return {
            'file_name': file_name,
            'file_hash': file_hash,
            'pdf_path': pdf_path,
            'json_path': json_path
        }
