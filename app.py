import os
import logging
from flask import Flask

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Configure upload settings
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Limit uploads to 50MB
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'apk'}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
