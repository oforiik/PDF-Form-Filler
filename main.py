from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.utils import secure_filename
import os
import pandas as pd
from fillpdf import fillpdfs
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib
import logging
from functools import wraps
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle
from datetime import datetime, timedelta
import base64
import json

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['UPLOAD_FOLDER'] = 'uploads'

# Load client secrets from the downloaded JSON file
client_secrets_file = '/Users/kevinofori/Downloads/client_secret_286392094018-mhubqajqn8h29ak78r38nq128alv723i.apps.googleusercontent.com.json'
with open(client_secrets_file) as f:
    client_config = json.load(f)

app.config['GOOGLE_CLIENT_ID'] = client_config['web']['client_id']
app.config['GOOGLE_CLIENT_SECRET'] = client_config['web']['client_secret']
app.config['GOOGLE_REDIRECT_URI'] = 'http://localhost:5001/oauth2callback'

# For development only - remove in production
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]

ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'pdf'}

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_google_auth_flow():
    flow = Flow.from_client_secrets_file(
        client_secrets_file,
        scopes=SCOPES,
        redirect_uri=app.config['GOOGLE_REDIRECT_URI']
    )
    return flow

def send_email(recipient_email, subject, body, attachment_path):
    try:
        # Load credentials from session
        creds = Credentials.from_authorized_user_info(session['credentials'])
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                # Update session with refreshed credentials
                session['credentials'] = {
                    'token': creds.token,
                    'refresh_token': creds.refresh_token,
                    'token_uri': creds.token_uri,
                    'client_id': creds.client_id,
                    'client_secret': creds.client_secret,
                    'scopes': creds.scopes
                }
            else:
                return False, "Invalid credentials. Please log in again."

        service = build('gmail', 'v1', credentials=creds)
        
        message = MIMEMultipart()
        message['to'] = recipient_email
        message['subject'] = subject

        message.attach(MIMEText(body, 'plain'))

        # Attach PDF
        with open(attachment_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename="{os.path.basename(attachment_path)}"'
            )
            message.attach(part)

        # Create the raw email
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        
        # Send the email
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        
        return True, "Email sent successfully!"
    except Exception as e:
        logger.error(f"Email error: {str(e)}")
        return False, str(e)

@app.route('/login')
def login():
    if 'user' in session:
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
        flow.fetch_token(
            authorization_response=request.url
        )
        
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
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        session['user'] = {
            'email': user_info['email'],
            'name': user_info.get('name', user_info['email']),
            'picture': user_info.get('picture', '')
        }
        
        logger.debug(f"Successfully authenticated user: {session['user']['email']}")
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return f"Authentication failed: {str(e)}", 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session.get('user'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    logger.debug("Upload endpoint called")
    logger.debug(f"Files in request: {request.files}")
    
    if 'excel_file' not in request.files or 'pdf_file' not in request.files:
        logger.error("Missing files in request")
        return jsonify({'error': 'Both files are required'}), 400
    
    excel_file = request.files['excel_file']
    pdf_file = request.files['pdf_file']
    
    logger.debug(f"Excel filename: {excel_file.filename}")
    logger.debug(f"PDF filename: {pdf_file.filename}")
    
    if excel_file.filename == '' or pdf_file.filename == '':
        logger.error("Empty filenames")
        return jsonify({'error': 'Both files must be selected'}), 400
    
    if not (allowed_file(excel_file.filename) and allowed_file(pdf_file.filename)):
        logger.error("Invalid file types")
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Create uploads directory if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Save files
    excel_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(excel_file.filename))
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(pdf_file.filename))
    
    excel_file.save(excel_path)
    pdf_file.save(pdf_path)
    
    logger.debug(f"Files saved to: {excel_path} and {pdf_path}")
    
    try:
        # Get PDF form fields
        logger.debug("Attempting to get PDF form fields")
        pdf_fields = fillpdfs.get_form_fields(pdf_path)
        logger.debug(f"PDF fields found: {pdf_fields}")
        
        if not pdf_fields:
            logger.error("No PDF form fields found")
            return jsonify({'error': 'No fillable fields found in the PDF'}), 400
        
        # Read Excel headers
        logger.debug("Reading Excel headers")
        df = pd.read_excel(excel_path)
        excel_headers = df.columns.tolist()
        logger.debug(f"Excel headers found: {excel_headers}")
        
        return jsonify({
            'pdf_fields': list(pdf_fields.keys()),
            'excel_headers': excel_headers,
            'excel_path': excel_path,
            'pdf_path': pdf_path
        })
    except Exception as e:
        logger.error(f"Error processing files: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/process', methods=['POST'])
@login_required
def process_files():
    logger.debug("Process endpoint called")
    data = request.json
    logger.debug(f"Received data: {data}")
    
    field_mapping = data.get('field_mapping')
    excel_path = data.get('excel_path')
    pdf_path = data.get('pdf_path')
    email_subject_template = data.get('email_subject', 'Your Filled Form')
    email_body_template = data.get('email_body', 'Please find your filled form attached.')
    
    logger.debug(f"Field mapping: {field_mapping}")
    logger.debug(f"Excel path: {excel_path}")
    logger.debug(f"PDF path: {pdf_path}")
    
    try:
        df = pd.read_excel(excel_path)
        logger.debug(f"Successfully read Excel file with {len(df)} rows")
        results = []
        
        for index, row in df.iterrows():
            logger.debug(f"Processing row {index}")
            # Create data dictionary for PDF filling
            data_dict = {pdf_field: str(row[excel_field]) for pdf_field, excel_field in field_mapping.items()}
            logger.debug(f"Created data dictionary: {data_dict}")
            
            # Generate output PDF name
            output_pdf = os.path.join(app.config['UPLOAD_FOLDER'], f'filled_{index}.pdf')
            logger.debug(f"Output PDF path: {output_pdf}")
            
            try:
                # Fill PDF
                logger.debug("Attempting to fill PDF")
                fillpdfs.write_fillable_pdf(pdf_path, output_pdf, data_dict)
                logger.debug("Successfully filled PDF")
                
                # Prepare email content with placeholders replaced
                row_dict = row.to_dict()
                email_subject = replace_placeholders(email_subject_template, row_dict)
                email_body = replace_placeholders(email_body_template, row_dict)
                
                # Send email
                recipient_email = row.get('Email Address')
                logger.debug(f"Recipient email: {recipient_email}")
                
                if recipient_email:
                    logger.debug(f"Sending email to {recipient_email}")
                    success, message = send_email(
                        recipient_email=recipient_email,
                        subject=email_subject,
                        body=email_body,
                        attachment_path=output_pdf
                    )
                    logger.debug(f"Email send result - Success: {success}, Message: {message}")
                    results.append({
                        'recipient': recipient_email,
                        'success': success,
                        'message': message
                    })
                else:
                    logger.warning(f"No email address found for row {index}")
                    results.append({
                        'recipient': 'Unknown',
                        'success': False,
                        'message': 'No email address found'
                    })
                
                # Clean up the generated PDF
                if os.path.exists(output_pdf):
                    os.remove(output_pdf)
                    logger.debug(f"Cleaned up temporary PDF: {output_pdf}")
                
            except Exception as e:
                logger.error(f"Error processing row {index}: {str(e)}")
                results.append({
                    'recipient': recipient_email if recipient_email else 'Unknown',
                    'success': False,
                    'message': str(e)
                })
        
        logger.debug(f"Processing completed. Results: {results}")
        return jsonify({'results': results})
        
    except Exception as e:
        logger.error(f"Process error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def replace_placeholders(template, data):
    """Replace placeholders in template with actual data."""
    result = template
    for key, value in data.items():
        placeholder = '{' + key + '}'
        result = result.replace(placeholder, str(value))
    return result

if __name__ == '__main__':
    app.run(debug=True, port=5001)
