from flask import Flask, render_template, request, session, cli
import os
import sys
import json
import uuid
from datetime import datetime

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

cli.show_server_banner = lambda *args: None

HISTORY_FILE = 'scan_history.json'

def save_to_history(result_data):
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []
    else:
        history = []
    
    result_data['id'] = str(uuid.uuid4())
    result_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    history.insert(0, result_data)
    
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=4)

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'selected_model' not in session:
        session['selected_model'] = 'qwen'
    
    if request.method == 'POST':
        if 'model_select' in request.form:
            session['selected_model'] = request.form['model_select']
            
        if 'file' in request.files:
            file = request.files['file']
            
            if file.filename == '':
                return "No valid file uploaded", 400
            
            if file and file.filename.endswith('.eml'):
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filepath)
                
                model_key = session.get('selected_model', 'qwen')
                model_func = MODELS[model_key]['function']
                
                try:
                    actual_results = model_func(filepath)
                    
                    if isinstance(actual_results, dict):
                        actual_results['model_used'] = MODELS[model_key]['name']
                    else:
                        actual_results = {
                            "error": "The model did not return the expected data format.",
                            "raw_output": str(actual_results),
                            "model_used": MODELS[model_key]['name']
                        }
                    
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
    scan_history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            try:
                scan_history = json.load(f)
            except json.JSONDecodeError:
                scan_history = []
                
    return render_template('History.html', history=scan_history)

@app.route('/report/<scan_id>')
def view_report(scan_id):
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
    if model_name in MODELS:
        session['selected_model'] = model_name
    return render_template('index.html', 
                         models=MODELS, 
                         selected_model=session['selected_model'])

if __name__ == '__main__':
    print("Starting PhishGuard server on http://127.0.0.1:5000 ...")
    app.run(debug=True, use_reloader=False)