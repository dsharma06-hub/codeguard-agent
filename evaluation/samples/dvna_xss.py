# DVNA Flask Server-Side Template Injection / Reflected XSS
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet_user():
    name = request.args.get('name', 'Guest')
    
    # Vulnerable SSTI/XSS: string formatting directly into Jinja2 template
    template = f"""
    <!DOCTYPE html>
    <html>
      <body>
        <h1>Hello, {name}!</h1>
        <p>Welcome to our platform.</p>
      </body>
    </html>
    """
    return render_template_string(template)
