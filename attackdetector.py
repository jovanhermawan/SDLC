import re
from flask import Flask, request, render_template, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

def generate_csrf_token():
    """
    Generate a CSRF token and store it in the session.
    """
    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token
    return csrf_token

def validate_csrf_token(request_token):
    """
    Validate the CSRF token against the one stored in the session.
    """
    if 'csrf_token' in session and session['csrf_token'] == request_token:
        return False
    else:
        return True

def is_malicious_request(user_input, request_token):
    # Check for SQL Injection
    if is_sql_injection(user_input):
        return "SQL_Injection"
    if is_xss_attack(user_input):
        return "XSS_Attack"
    if validate_csrf_token(request_token):
        return "CSRF_Attack"

    # Add more checks for other types of attacks (XSS, XSRF, DOS, DDOS, LFI, Unauthorized remote access, unhandled exceptions, bufferoverflow)

    # If none of the checks match, consider the request as non-malicious
    return False

def is_sql_injection(user_input):
    # Check for common SQL injection patterns
    sql_injection_patterns = [
        r'\b(union\s+all|union|select|insert|update|delete|alter|drop|truncate|create|execute)\b',
        r'\b(\/\*|\*\/|--|#|@@|\bexec\b)\b',
        r'\b(declare|cast|xp_cmdshell|/\*!\*/|nvl|chr|concat)\b',
        r'\b(\blike\b.*\bselect\b|\bselect\b.*\bfrom\b|\bexec\b.*\bselect\b)\b'
    ]

    for pattern in sql_injection_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True

    # If none of the patterns match, consider the input as non-malicious
    return False

def is_xss_attack(user_input):
    # Check for common XSS patterns
    xss_patterns = [
        r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
        r'javascript:',
        r'on\w+\s*=\s*["\'][^"\']*["\']',
        r'(<\s*\/?\s*)(script)',
        r'%3Cscript',
        r'\balert\s*\('
    ]

    for pattern in xss_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True

    # If none of the patterns match, consider the input as non-malicious
    return False

@app.route('/')
def index():
    # Generate CSRF token and render the template
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)

@app.route('/process_data', methods=['POST'])
def process_data():
    # Get the CSRF token from the request
    user_input = request.form.get('data')
    request_csrf_token = request.form.get('csrf_token')
    result = is_malicious_request(user_input,request_csrf_token)
    if result:
        return result
    else:
        return("Request is not malicious.")
    # Validate the CSRF token

if __name__ == '__main__':
    app.run(debug=True)
# Example usage


    