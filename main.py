from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from mobsf_analyzer import MobSFClient
from mobsf_json_parser import extract_mobsf_summary
from andropytool_lib import AndroPyToolClient
from ml_predictor import MLPredictor
from datetime import datetime
import os
import json
import shutil

# Initialize the ML predictor
predictor = MLPredictor()

# Flask app and analysis clients
app = Flask(__name__)
mobsf = MobSFClient()

andropy = AndroPyToolClient(
    vt_key_path='config/VTkey.txt',
    enable_all=False,
    enable_dynamic=True,
    enable_virustotal=True
)

# Configurations
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 80 * 1024 * 1024  # 80MB
app.config['ALLOWED_EXTENSIONS'] = {'apk'}

# File validation
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# File upload + analysis route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        print(f"[DEBUG] Uploaded filename: {filename}")

        # Create subfolder: appName_timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        app_name = filename.rsplit('.', 1)[0]
        subfolder_name = f"{app_name}_{timestamp}"
        subfolder_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder_name)
        os.makedirs(subfolder_path, exist_ok=True)

        # Save the file
        apk_path = os.path.join(subfolder_path, filename)
        file.save(apk_path)

        # Run MobSF
        try:
            result = mobsf.analyze_apk(apk_path)
        except Exception as e:
            print(f"[!] MobSF analysis failed: {e}")
            return 'MobSF analysis failed', 500

        if result:
            print("[+] mobsf analysis completed.")
            file_name = result['file_name']
            json_report = f'{file_name}_report.json'
            pdf_report = f'{file_name}_report.pdf'

            # Run AndroPyTool
            try:
                andropy_output_dir = os.path.join(subfolder_path, 'andropy_output')
                os.makedirs(andropy_output_dir, exist_ok=True)
                andropy.run_analysis(apk_path, andropy_output_dir)
                print("[+] AndroPyTool analysis completed.")
            except Exception as e:
                print(f"[!] AndroPyTool analysis failed: {e}")

            # Load features and run ML prediction
            # Load features and run ML prediction (robust feature file detection)
            features_dir = os.path.join(subfolder_path, 'Features_files')
            if os.path.exists(features_dir):
                feature_files = [
                    f for f in os.listdir(features_dir)
                    if f.endswith('-analysis.json') and not f.startswith('OUTPUT_ANDROPY')
                ]

                if feature_files:
                    features_path = os.path.join(features_dir, feature_files[0])
                    print(f"[INFO] Using feature file for prediction: {features_path}")
                    try:
                        prediction_result = predictor.predict_all(features_path)
                        print("[+] ML prediction:", prediction_result)
                        with open(os.path.join(subfolder_path, 'ml_prediction.json'), 'w') as f:
                            json.dump(prediction_result, f, indent=2)
                    except Exception as e:
                        print(f"[!] ML prediction failed: {e}")
                else:
                    print("[WARNING] No valid feature file found in Features_files.")
            else:
                print("[WARNING] Features_files directory not found.")


            # Move MobSF reports to subfolder
            root_json = os.path.join(app.config['UPLOAD_FOLDER'], json_report)
            root_pdf = os.path.join(app.config['UPLOAD_FOLDER'], pdf_report)
            if os.path.exists(root_json):
                shutil.move(root_json, os.path.join(subfolder_path, json_report))
            if os.path.exists(root_pdf):
                shutil.move(root_pdf, os.path.join(subfolder_path, pdf_report))

            return redirect(url_for('results',
                                    file_name=file_name,
                                    file_hash=result['file_hash']))

    return 'Invalid file or analysis failed', 400

# Result display route
@app.route('/results/<file_name>/<file_hash>')
def results(file_name, file_hash):
    folder = request.args.get('folder')
    if not folder:
        return 'Missing folder info', 400

    subfolder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
    pdf_path = os.path.join(subfolder_path, f'{file_name}_report.pdf')
    json_path = os.path.join(subfolder_path, f'{file_name}_report.json')
    prediction_path = os.path.join(subfolder_path, 'ml_prediction.json')

    context = {
        'file_name': file_name,
        'file_hash': file_hash,
        'pdf_exists': os.path.exists(pdf_path),
        'report': None,
        'prediction': None,
        'error': None
    }

    if os.path.exists(json_path):
        try:
            context['report'] = extract_mobsf_summary(json_path)
        except Exception as e:
            context['error'] = f"Failed to parse MobSF JSON: {str(e)}"

    if os.path.exists(prediction_path):
        try:
            with open(prediction_path, 'r') as f:
                context['prediction'] = json.load(f)
        except Exception as e:
            context['error'] = f"Failed to parse prediction results: {str(e)}"

    return render_template('results.html', **context)

# Download report route
@app.route('/download/<file_name>/<report_type>')
def download_report(file_name, report_type):
    filename = f'{file_name}_report.{report_type}'
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True
    )

# Run server
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5050, debug=True)
