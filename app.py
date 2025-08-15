from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.exceptions import BadRequestKeyError, HTTPException
from markupsafe import escape
import os
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Use environment variable for secret key in production
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

def sanitize_input(text):
    """
    Sanitize user input by removing HTML tags and limiting length
    """
    # Remove HTML tags
    clean_text = re.sub(r'<[^>]*>', '', text)
    # Limit length to prevent overflow attacks
    clean_text = clean_text[:50]
    # Remove special characters
    clean_text = re.sub(r'[^a-zA-Z0-9\s]', '', clean_text)
    return clean_text.strip()

@app.route('/')
def index():
    """Render the index page with the name input form."""
    return render_template('index.html')

@app.route('/greet', methods=['POST'])
def greet():
    """Handle the form submission and display a personalized greeting."""
    try:
        # Get and sanitize username
        raw_username = request.form.get('username', '').strip()
        if not raw_username:
            flash('Please enter your name!', 'error')
            return redirect(url_for('index'))
        
        # Sanitize and escape username
        username = sanitize_input(raw_username)
        
        # Log attempt if original input was potentially malicious
        if username != raw_username:
            logger.warning(f'Potential XSS attempt detected. Original input: {raw_username}')
            flash('Invalid characters removed from input', 'warning')
        
        if not username:
            flash('Please enter a valid name using only letters and numbers', 'error')
            return redirect(url_for('index'))
        
        logger.info(f'Greeting user: {username}')
        # Use escape() when passing to template for additional security
        return render_template('greet.html', username=escape(username))
    
    except BadRequestKeyError as e:
        logger.error(f'Bad request error: {str(e)}')
        flash('Something went wrong with your request!', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f'Unexpected error: {str(e)}')
        flash('An unexpected error occurred!', 'error')
        return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors by showing a custom page."""
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all other exceptions."""
    logger.error(f'Unhandled exception: {str(e)}')
    if isinstance(e, HTTPException):
        return render_template('404.html'), e.code
    return render_template('404.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )