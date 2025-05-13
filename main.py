# main.py


from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from mobsf_analyzer import MobSFClient
from mobsf_json_parser import extract_mobsf_summary
from datetime import datetime
import os
import json
import shutil


# object definations
app = Flask(__name__)
mobsf = MobSFClient()

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 80 * 1024 * 1024  # 80MB limit
app.config['ALLOWED_EXTENSIONS'] = {'apk'}

# file extension_check function
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# home directory
@app.route('/')
def index():
    return render_template('index.html')


# upload_method
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Create unique subfolder: app_name + timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        app_name = filename.rsplit('.', 1)[0]
        subfolder_name = f"{app_name}_{timestamp}"
        subfolder_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder_name)
        os.makedirs(subfolder_path, exist_ok=True)

        # Save APK in that subfolder
        apk_path = os.path.join(subfolder_path, filename)
        file.save(apk_path)

        # Analyze with MobSF
        result = mobsf.analyze_apk(apk_path)

        if result:
            file_name = result['file_name']

            # Define expected report file names
            json_report = f'{file_name}_report.json'
            pdf_report = f'{file_name}_report.pdf'

            # Paths where MobSF likely saved them (in root uploads folder)
            root_json = os.path.join(app.config['UPLOAD_FOLDER'], json_report)
            root_pdf = os.path.join(app.config['UPLOAD_FOLDER'], pdf_report)

            # Move reports to the subfolder
            if os.path.exists(root_json):
                shutil.move(root_json, os.path.join(subfolder_path, json_report))
            if os.path.exists(root_pdf):
                shutil.move(root_pdf, os.path.join(subfolder_path, pdf_report))

            # Pass subfolder name along if needed later
            return redirect(url_for('results',
                                    file_name=file_name,
                                    file_hash=result['file_hash'],
                                    folder=subfolder_name))
    
    return 'Invalid file or analysis failed', 400




@app.route('/results/<file_name>/<file_hash>')
def results(file_name, file_hash):
    folder = request.args.get('folder')  # Get folder from query params

    if not folder:
        return 'Missing folder information', 400

    subfolder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
    pdf_path = os.path.join(subfolder_path, f'{file_name}_report.pdf')
    json_path = os.path.join(subfolder_path, f'{file_name}_report.json')

    context = {
        'file_name': file_name,
        'file_hash': file_hash,
        'pdf_exists': os.path.exists(pdf_path),
        'report': None,
        'error': None
    }

    if os.path.exists(json_path):
        try:
            context['report'] = extract_mobsf_summary(json_path)
        except Exception as e:
            context['error'] = f"Report processing failed: {str(e)}"

    return render_template('results.html', **context)


@app.route('/download/<file_name>/<report_type>')
def download_report(file_name, report_type):
    
    filename = f'{file_name}_report.{report_type}'
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True
    )

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5050, debug=True)
