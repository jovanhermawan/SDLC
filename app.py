from flask import Flask

app = Flask(__name__)

@app.route("/")
def main_app():
    return "<p>Hello, World!</p>"

@app.route("/checker")
def checker():
    # Temporarily add run_checks function - will be sending a text for validation of security input
    run_checks(resp)
    return "<p>Done check</p>"

def run_checks(input_text: str):
    return "ok"

