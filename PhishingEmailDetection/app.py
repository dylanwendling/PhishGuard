from flask import Flask, render_template, request, session, cli, redirect
import os
import sys
import json
import uuid
from datetime import datetime
import email
from email import policy
from main import analyze_text_snippet as snippet_smollm
from main_two import analyze_text_snippet as snippet_llama3
from main_three import analyze_text_snippet as snippet_qwen

SNIPPET_MODELS = {
    'smollm': snippet_smollm,
    'llama3': snippet_llama3,
    'qwen': snippet_qwen
}

from main import run_phishguard_model as run_smollm
from main_two import run_phishguard_model as run_llama3
from main_three import run_phishguard_model as run_qwen

app = Flask(__name__)
app.secret_key = 'phishguard-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

MODELS = {
    'smollm': {'name': 'SmolLM2-135M', 'function': run_smollm, 'speed': '⚡ Fastest'},
    'llama3': {'name': 'Llama-3.2-1B', 'function': run_llama3, 'speed': '⚖️ Balanced'},
    'qwen': {'name': 'Qwen2.5-1.5B', 'function': run_qwen, 'speed': '🎯 Most Accurate'}
}

# Safely disables the Flask startup banner that causes colorama to crash in Jupyter terminals
cli.show_server_banner = lambda *args: None

HISTORY_FILE = 'scan_history.json'

def save_to_history(result_data):
    # Loads existing history or creates an empty list if the file does not exist
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []
    else:
        history = []
    
    # Generates a unique ID and timestamp for the new scan
    result_data['id'] = str(uuid.uuid4())
    result_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Adds the new result to the beginning of the list
    history.insert(0, result_data)
    
    # Saves the updated list back to the file
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=4)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Sets default model to Qwen if not already set
    if 'selected_model' not in session:
        session['selected_model'] = 'qwen'
    
    if request.method == 'POST':
        # Updates the selected model based on user input
        if 'model_select' in request.form:
            session['selected_model'] = request.form['model_select']
            
        # Processes the uploaded file
        if 'file' in request.files:
            file = request.files['file']
            
            # Validates that a file was actually selected
            if file.filename == '':
                return "No valid file uploaded", 400
            
            # Checks for the correct .eml file extension
            if file and file.filename.endswith('.eml'):
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filepath)
                
                model_key = session.get('selected_model', 'qwen')
                model_func = MODELS[model_key]['function']
                
                try:
                    # Runs the selected model on the file
                    actual_results = model_func(filepath)
                    
                    # Formats the results dictionary to ensure compatibility
                    if isinstance(actual_results, dict):
                        actual_results['model_used'] = MODELS[model_key]['name']
                    else:
                        actual_results = {
                            "error": "The model did not return the expected data format.",
                            "raw_output": str(actual_results),
                            "model_used": MODELS[model_key]['name']
                        }
                    
                    # Saves the successful scan to the history file
                    save_to_history(actual_results)
                    
                    return render_template('results.html', results=actual_results)
                    
                except Exception as e:
                    return f"Model Error: {str(e)}", 500
            else:
                return "Please upload an .eml file.", 400

    return render_template('index.html', 
                         models=MODELS, 
                         selected_model=session['selected_model'])

@app.route('/history')
def history():
    # Loads the history data to pass to the template
    scan_history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            try:
                scan_history = json.load(f)
            except json.JSONDecodeError:
                scan_history = []
                
    return render_template('History.html', history=scan_history)

@app.route('/clear_history', methods=['POST'])
def clear_history():
    # Deletes the history file if it exists
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    
    # Redirects the user back to the history page to see the empty state
    return redirect('/history')

@app.route('/report/<scan_id>')
def view_report(scan_id):
    # Searches the history file for the specific scan ID and returns its data
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            try:
                history = json.load(f)
                for item in history:
                    if item.get('id') == scan_id or item.get('timestamp') == scan_id:
                        return render_template('results.html', results=item)
            except json.JSONDecodeError:
                pass
                
    return "Report not found.", 404

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/faq')
def faq():
    return render_template('FAQ.html')

@app.route('/common_breaches')
def common_breaches():
    return render_template('Common_Breaches.html')

@app.route('/howto')
def howto():
    return render_template('Howto.html')

@app.route('/set_model/<model_name>')
def set_model(model_name):
    # Changes the model in the session based on user selection
    if model_name in MODELS:
        session['selected_model'] = model_name
    return render_template('index.html', 
                         models=MODELS, 
                         selected_model=session['selected_model'])

@app.route('/realtime')
def realtime():
    # Renders the real-time interactive analysis page
    if 'selected_model' not in session:
        session['selected_model'] = 'qwen'
    return render_template('realtime.html', 
                         models=MODELS, 
                         selected_model=session['selected_model'])

@app.route('/api/extract_email', methods=['POST'])
def extract_email():
    # Parses the uploaded eml file and returns the plain text body
    if 'file' not in request.files:
        return {"error": "No file uploaded"}, 400
    
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.eml'):
        return {"error": "Please upload a valid .eml file"}, 400

    try:
        msg = email.message_from_binary_file(file.stream, policy=policy.default)
        body = msg.get_body(preferencelist=('plain'))
        text_content = body.get_content() if body else "Could not extract text."
        return {"text": text_content}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api/analyze_snippet', methods=['POST'])
def analyze_snippet():
    # Accepts a text snippet and selected model to return a threat analysis and score
    data = request.json
    snippet = data.get('text', '')
    model_key = data.get('model', 'qwen')
    
    model_func = SNIPPET_MODELS.get(model_key, snippet_qwen)
    
    try:
        result = model_func(snippet)
        return result
    except Exception as e:
        return {"analysis": f"Model Error: {str(e)}", "score": 0}, 500

if __name__ == '__main__':
    # Prints a plain-text confirmation so you know it's running
    print("Starting PhishGuard server on http://127.0.0.1:5000 ...")
    app.run(debug=True, use_reloader=False)