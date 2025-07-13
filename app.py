from flask import Flask, render_template, request, redirect, url_for, session, jsonify
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
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import io
import re

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls', 'pdf'}

# Load Google OAuth config
try:
    with open('client_secrets.json') as f:
        client_config = json.load(f)
        app.config['GOOGLE_CLIENT_ID'] = client_config['web']['client_id']
        app.config['GOOGLE_CLIENT_SECRET'] = client_config['web']['client_secret']
        app.config['GOOGLE_REDIRECT_URI'] = client_config['web']['redirect_uris'][0]
except FileNotFoundError:
    logger.error("client_secrets.json not found. Please create this file with your Google OAuth credentials.")
    app.config['GOOGLE_CLIENT_ID'] = None
    app.config['GOOGLE_CLIENT_SECRET'] = None
    app.config['GOOGLE_REDIRECT_URI'] = None

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
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_google_auth_flow():
    if not app.config['GOOGLE_CLIENT_ID']:
        raise ValueError("Google OAuth not configured")
    return Flow.from_client_secrets_file(
        'client_secrets.json',
        scopes=SCOPES,
        redirect_uri=app.config['GOOGLE_REDIRECT_URI']
    )

def get_credentials():
    """Get valid credentials from session"""
    if 'credentials' not in session:
        return None
    
    credentials = Credentials(**session['credentials'])
    
    # Refresh if expired
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    
    return credentials

def send_email_with_attachment(recipient_email, subject, body, attachment_path, attachment_name):
    """Send email with PDF attachment using Gmail API"""
    try:
        credentials = get_credentials()
        if not credentials:
            return False, "No valid credentials"
        
        service = build('gmail', 'v1', credentials=credentials)
        
        # Create message
        message = MIMEMultipart()
        message['to'] = recipient_email
        message['subject'] = subject
        
        # Add body
        message.attach(MIMEText(body, 'plain'))
        
        # Add attachment
        if os.path.exists(attachment_path):
            with open(attachment_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {attachment_name}'
                )
                message.attach(part)
        
        # Convert to base64
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        
        # Send message
        result = service.users().messages().send(
            userId='me',
            body={'raw': raw_message}
        ).execute()
        
        return True, f"Message sent successfully. Message ID: {result['id']}"
        
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return False, str(e)

def replace_placeholders(text, row_data):
    """Replace placeholders in text with values from row data"""
    for column, value in row_data.items():
        placeholder = f"{{{column}}}"
        text = text.replace(placeholder, str(value))
    return text

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session.get('user'))

@app.route('/login')
def login():
    if 'credentials' in session:
        return redirect(url_for('index'))
    
    try:
        flow = get_google_auth_flow()
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        session['state'] = state
        return render_template('login.html', auth_url=authorization_url)
    except ValueError as e:
        return render_template('error.html', message=str(e)), 500

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
        return render_template('error.html', message=f"Authentication failed: {str(e)}"), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    try:
        if 'excel_file' not in request.files or 'pdf_file' not in request.files:
            return jsonify({'error': 'Both files are required'}), 400
        
        excel_file = request.files['excel_file']
        pdf_file = request.files['pdf_file']
        
        if not (allowed_file(excel_file.filename) and allowed_file(pdf_file.filename)):
            return jsonify({'error': 'Invalid file types'}), 400

        # Create upload directory
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save files
        excel_filename = secure_filename(excel_file.filename)
        pdf_filename = secure_filename(pdf_file.filename)
        excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
        
        excel_file.save(excel_path)
        pdf_file.save(pdf_path)

        # Get PDF fields
        pdf_fields = fillpdfs.get_form_fields(pdf_path)
        logger.debug(f"Detected PDF fields: {list(pdf_fields.keys()) if pdf_fields else 'None'}")
        
        if not pdf_fields:
            return jsonify({'error': 'No fillable fields found in PDF'}), 400

        # Get Excel headers
        try:
            df = pd.read_excel(excel_path)
            excel_headers = df.columns.tolist()
        except Exception as e:
            return jsonify({'error': f'Error reading Excel file: {str(e)}'}), 400
        
        # Store file paths in session
        session['excel_path'] = excel_path
        session['pdf_path'] = pdf_path
        
        return jsonify({
            'pdf_fields': list(pdf_fields.keys()),
            'excel_headers': excel_headers,
            'excel_path': excel_path,
            'pdf_path': pdf_path
        })
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/process', methods=['POST'])
@login_required
def process_files():
    try:
        data = request.get_json()
        field_mapping = data.get('field_mapping', {})
        excel_path = data.get('excel_path') or session.get('excel_path')
        pdf_path = data.get('pdf_path') or session.get('pdf_path')
        email_subject = data.get('email_subject', 'Your Filled Form')
        email_body = data.get('email_body', 'Please find attached your filled form.')
        
        if not excel_path or not pdf_path:
            return jsonify({'error': 'File paths not found'}), 400
        
        if not os.path.exists(excel_path) or not os.path.exists(pdf_path):
            return jsonify({'error': 'Files not found'}), 400
        
        # Read Excel data
        df = pd.read_excel(excel_path)
        results = []
        
        # Check if email column exists
        email_column = None
        for col in df.columns:
            if 'email' in col.lower() or 'mail' in col.lower():
                email_column = col
                break
        
        if not email_column:
            return jsonify({'error': 'No email column found in Excel file'}), 400
        
        for index, row in df.iterrows():
            recipient_email = row.get(email_column)
            
            if not recipient_email or pd.isna(recipient_email):
                results.append({
                    'row': index + 1,
                    'recipient': 'No email',
                    'success': False,
                    'message': 'No email address found'
                })
                continue
            
            try:
                # Create data dictionary for PDF filling
                data_dict = {}
                for pdf_field, excel_field in field_mapping.items():
                    if excel_field and excel_field in row:
                        value = row[excel_field]
                        data_dict[pdf_field] = str(value) if pd.notna(value) else ''
                
                # Create filled PDF
                output_pdf = os.path.join(app.config['UPLOAD_FOLDER'], f'filled_{index}_{recipient_email}.pdf')
                fillpdfs.write_fillable_pdf(pdf_path, output_pdf, data_dict)
                
                # Prepare email content with placeholders
                personalized_subject = replace_placeholders(email_subject, row)
                personalized_body = replace_placeholders(email_body, row)
                
                # Send email
                success, message = send_email_with_attachment(
                    recipient_email,
                    personalized_subject,
                    personalized_body,
                    output_pdf,
                    f'filled_form_{index}.pdf'
                )
                
                results.append({
                    'row': index + 1,
                    'recipient': recipient_email,
                    'success': success,
                    'message': message
                })
                
                # Clean up PDF file
                if os.path.exists(output_pdf):
                    os.remove(output_pdf)
                    
            except Exception as e:
                logger.error(f"Error processing row {index}: {str(e)}")
                results.append({
                    'row': index + 1,
                    'recipient': recipient_email,
                    'success': False,
                    'message': str(e)
                })
        
        return jsonify({'results': results})
        
    except Exception as e:
        logger.error(f"Processing error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'oauth_configured': app.config['GOOGLE_CLIENT_ID'] is not None
    })

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only
    app.run(debug=True, port=5001)