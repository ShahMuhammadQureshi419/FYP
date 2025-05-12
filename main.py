# main.py


from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from mobsf_analyzer import MobSFClient
from mobsf_json_parser import extract_mobsf_summary
import os
import json


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
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze with MobSF
        result = mobsf.analyze_apk(filepath)
        
        if result:
            return redirect(url_for('results', 
                                 file_name=result['file_name'],
                                 file_hash=result['file_hash']))
        
    return 'Invalid file or analysis failed', 400



@app.route('/results/<file_name>/<file_hash>')
def results(file_name, file_hash):

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{file_name}_report.pdf')
    json_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{file_name}_report.json')

    context = {
        'file_name': file_name,
        'file_hash': file_hash,
        'pdf_exists': os.path.exists(pdf_path),
        'report': None,
        'error': None
    }

    if os.path.exists(json_path):
        try:
            context['report'] = extract_mobsf_summary(json_path)  # Use the parser
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
