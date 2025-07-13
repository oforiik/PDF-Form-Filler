from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
import os
import pandas as pd
from fillpdf import fillpdfs
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import json
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls', 'pdf'}

# Load Google OAuth config
with open('client_secrets.json') as f:
    client_config = json.load(f)
    app.config['GOOGLE_CLIENT_ID'] = client_config['web']['client_id']
    app.config['GOOGLE_CLIENT_SECRET'] = client_config['web']['client_secret']
    app.config['GOOGLE_REDIRECT_URI'] = client_config['web']['redirect_uris'][0]

SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'credentials' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_google_auth_flow():
    return Flow.from_client_secrets_file(
        'client_secrets.json',
        scopes=SCOPES,
        redirect_uri=app.config['GOOGLE_REDIRECT_URI']
    )

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session.get('user'))

@app.route('/login')
def login():
    if 'credentials' in session:
        return redirect(url_for('index'))
    
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return render_template('login.html', auth_url=authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    try:
        flow = get_google_auth_flow()
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Get user info
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        
        session['user'] = {
            'email': user_info['email'],
            'name': user_info.get('name', 'User'),
            'picture': user_info.get('picture', '')
        }
        
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}")
        return f"Authentication failed: {str(e)}", 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    try:
        if 'excel_file' not in request.files or 'pdf_file' not in request.files:
            return render_template('error.html', message="Both files are required"), 400
        
        excel_file = request.files['excel_file']
        pdf_file = request.files['pdf_file']
        
        if not (allowed_file(excel_file.filename) and allowed_file(pdf_file.filename)):
            return render_template('error.html', message="Invalid file types"), 400

        # Create upload directory
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save files
        excel_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(excel_file.filename))
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(pdf_file.filename))
        excel_file.save(excel_path)
        pdf_file.save(pdf_path)

        # Get PDF fields
        pdf_fields = fillpdfs.get_form_fields(pdf_path)
        logger.debug(f"Detected PDF fields: {list(pdf_fields.keys())}")
        
        if not pdf_fields:
            return render_template('error.html', message="No fillable fields found in PDF"), 400

        # Get Excel headers
        df = pd.read_excel(excel_path)
        excel_headers = df.columns.tolist()
        
        return render_template('mapping.html',
            pdf_fields=list(pdf_fields.keys()),
            excel_headers=excel_headers,
            excel_path=excel_path,
            pdf_path=pdf_path
        )
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return render_template('error.html', message=str(e)), 500

@app.route('/process', methods=['POST'])
@login_required
def process_files():
    try:
        field_mapping = request.form.to_dict()
        excel_path = request.form['excel_path']
        pdf_path = request.form['pdf_path']
        
        df = pd.read_excel(excel_path)
        results = []
        
        for index, row in df.iterrows():
            data_dict = {pdf_field: str(row[excel_field]) for pdf_field, excel_field in field_mapping.items() if excel_field}
            output_pdf = os.path.join(app.config['UPLOAD_FOLDER'], f'filled_{index}.pdf')
            
            try:
                fillpdfs.write_fillable_pdf(pdf_path, output_pdf, data_dict)
                
                # Email sending logic would go here
                results.append({
                    'recipient': 'test@example.com',
                    'success': True,
                    'message': 'Mock email sent successfully'
                })
                
                os.remove(output_pdf)
            except Exception as e:
                results.append({
                    'recipient': 'error@example.com',
                    'success': False,
                    'message': str(e)
                })
        
        return render_template('results.html', results=results)
    except Exception as e:
        logger.error(f"Processing error: {str(e)}")
        return render_template('error.html', message=str(e)), 500

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only
    app.run(debug=True, port=5001)