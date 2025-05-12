import os
import logging
import uuid
from flask import render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from app import app
from analyzer import analyze_apk

# Helper to check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    """Main page with file upload functionality"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle APK file upload and start analysis"""
    # Check if file was included in request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    # Check if user submitted an empty form
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check if file is APK
    if file and allowed_file(file.filename):
        # Generate a safe filename with unique ID
        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        session_filename = f"{unique_id}_{filename}"
        
        # Save file to upload folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], session_filename)
        file.save(file_path)
        
        # Store the file info in session
        session['apk_file'] = {
            'path': file_path,
            'original_name': filename,
            'unique_id': unique_id
        }
        
        # Trigger the analysis
        logging.debug(f"Starting analysis of {filename}")
        
        try:
            # Call the analyzer module to process the APK
            analysis_result = analyze_apk(file_path)
            
            # Store the results in session for the results page
            session['analysis_result'] = analysis_result
            
            return jsonify({
                'success': True,
                'redirect': url_for('show_results')
            })
            
        except Exception as e:
            logging.error(f"Analysis error: {str(e)}")
            return jsonify({'error': f"Analysis failed: {str(e)}"}), 500
    
    return jsonify({'error': 'Invalid file format. Only APK files are allowed'}), 400

@app.route('/results')
def show_results():
    """Display the APK analysis results"""
    # Check if we have analysis results in the session
    if 'analysis_result' not in session:
        flash('No analysis results found. Please upload an APK file first.', 'error')
        return redirect(url_for('index'))
    
    # Get the analysis results and file info from session
    analysis_result = session['analysis_result']
    file_info = session.get('apk_file', {})
    original_filename = file_info.get('original_name', 'Unknown file')
    
    return render_template(
        'results.html',
        filename=original_filename,
        result=analysis_result
    )

@app.route('/api/results')
def get_results_api():
    """API endpoint to get the latest analysis results as JSON"""
    if 'analysis_result' not in session:
        return jsonify({'error': 'No analysis results found'}), 404
        
    return jsonify(session['analysis_result'])

@app.errorhandler(413)
def file_too_large(error):
    """Handle file size too large error"""
    return jsonify({'error': 'File too large. Maximum size is 50MB'}), 413
