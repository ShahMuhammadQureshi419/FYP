from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from werkzeug.utils import secure_filename
from mobsf_analyzer import MobSFClient
from mobsf_json_parser import extract_mobsf_summary
from andropytool_lib import AndroPyToolClient
from ml_predictor import MLPredictor
from datetime import datetime
import os
import json
import shutil

# Initialize ML predictor and analysis tools
predictor = MLPredictor()
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        app_name = filename.rsplit('.', 1)[0]
        subfolder_name = f"{app_name}_{timestamp}"
        subfolder_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder_name)
        os.makedirs(subfolder_path, exist_ok=True)

        apk_path = os.path.join(subfolder_path, filename)
        file.save(apk_path)

        try:
            result = mobsf.analyze_apk(apk_path)
        except Exception as e:
            error_msg = f"MobSF analysis failed: {e}"
            print(f"[!] {error_msg}")
            return jsonify({'error': error_msg}), 500


        if result:
            file_name = result['file_name']
            json_report = f'{file_name}_report.json'
            pdf_report = f'{file_name}_report.pdf'

            try:
                andropy_output_dir = os.path.join(subfolder_path, 'andropy_output')
                os.makedirs(andropy_output_dir, exist_ok=True)
                andropy.run_analysis(apk_path, andropy_output_dir)
            except Exception as e:
                error_msg = f"AndroPyTool analysis failed: {e}"
                print(f"[!] {error_msg}")
                return jsonify({'error': error_msg}), 500


            features_dir = os.path.join(subfolder_path, 'Features_files')
            if os.path.exists(features_dir):
                feature_files = [
                    f for f in os.listdir(features_dir)
                    if f.endswith('-analysis.json') and not f.startswith('OUTPUT_ANDROPY')
                ]
                if feature_files:
                    features_path = os.path.join(features_dir, feature_files[0])
                    try:
                        prediction_result = predictor.predict_all(features_path)
                        with open(os.path.join(subfolder_path, 'ml_prediction.json'), 'w') as f:
                            json.dump(prediction_result, f, indent=2)
                    except Exception as e:
                            error_msg = f"ML prediction failed: {e}"
                            print(f"[!] {error_msg}")
                            return jsonify({'error': error_msg}), 500


            root_json = os.path.join(app.config['UPLOAD_FOLDER'], json_report)
            root_pdf = os.path.join(app.config['UPLOAD_FOLDER'], pdf_report)
            if os.path.exists(root_json):
                shutil.move(root_json, os.path.join(subfolder_path, json_report))
            if os.path.exists(root_pdf):
                shutil.move(root_pdf, os.path.join(subfolder_path, pdf_report))
            print("Redirect URL:", url_for('results', file_name=file_name, file_hash=result.get('sha256'), folder=subfolder_name))
            return jsonify({
                'redirect_url': url_for('results',
                                        file_name=file_name,
                                        file_hash=result.get('sha256'),
                                        folder=subfolder_name)
            }), 200


    return jsonify({'error': 'Invalid file or analysis failed'}), 400

@app.route('/results')
def results():
    file_name = request.args.get('file_name')
    file_hash = request.args.get('file_hash')
    folder = request.args.get('folder')

    prediction_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, 'ml_prediction.json')
    prediction = None
    if os.path.exists(prediction_path):
        with open(prediction_path) as f:
            prediction = json.load(f)

    summary_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, f'{file_name}_report.json')
    report = None
    if os.path.exists(summary_path):
        report = extract_mobsf_summary(summary_path)  # ✅ FIXED HERE


    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, f'{file_name}_report.pdf')
    pdf_exists = os.path.exists(pdf_path)

    return render_template('results.html',
                           file_name=file_name,
                           file_hash=file_hash,
                           folder=folder,
                           prediction=prediction,
                           report=report,
                           pdf_exists=pdf_exists)

@app.route('/download')
def download_report():
    file_name = request.args.get('file_name')
    report_type = request.args.get('report_type')
    folder = request.args.get('folder')

    filename = f'{file_name}_report.{report_type}'
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, filename)

    if not os.path.exists(file_path):
        return 'File not found', 404

    return send_from_directory(os.path.dirname(file_path), os.path.basename(file_path), as_attachment=True)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5050, debug=True)
