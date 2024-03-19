from flask import Flask, render_template, request, redirect, url_for
import requests
import json
import sys
import colorama
from time import sleep
from PyPDF2 import PdfReader
from io import BytesIO
import re

colorama.init()

def print_slow(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def scan_file(file_data, api_key):
    url = r'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {"apikey": api_key}

    try:
        files = {'file': file_data}
        response = requests.post(url, files=files, params=params)
        if response.status_code == 200:
            file_id = response.json()['resource']
            return file_id
        else:
            print(colorama.Fore.RED + f"Error uploading file: {response.status_code}")
            return None
    except Exception as e:
        print(colorama.Fore.RED + f"Error: {e}")
        return None

def get_report(file_id, api_key):
    if file_id:
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {"apikey": api_key, "resource": file_id}

        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                report = response.json()
                return report
            else:
                print(colorama.Fore.RED + f"Error retrieving report: {response.status_code}")
                return None
        except Exception as e:
            print(colorama.Fore.RED + f"Error retrieving report: {e}")
            return None
    else:
        return None

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file.filename == '':
            return "No selected file"

        api_key = "00dd05020a99baef64f164b8989ff918cd8c90fc5228bfe80c3cf368612f207a"  # Replace with your actual VirusTotal API key

        file_id = scan_file(file, api_key)
        if file_id:
            print_slow(colorama.Fore.YELLOW + "Analyzing...\n")
            report = get_report(file_id, api_key)
            return render_template('result.html', report=report)
        else:
            return "Scan failed. Please check the file and try again."

    return render_template('1m.html')

@app.route('/job', methods=['GET', 'POST'])
def job():
    if request.method == 'POST':
        # Process form data from job.html
        data = {
            'name': request.form['name'],
            'job': request.form['job']
        }
        # Redirect to job.html with the form data
        return redirect(url_for('job'))
    else:
        # Render job.html
        return render_template('job.html')


@app.route('/orders')
def orders():
    return render_template('orders.html')

@app.route('/help')
def help():
    return render_template('help.html')


def validate_form(name, job, file):
    valid_extensions = ['.pdf', '.doc', '.docx']
    name_regex = r"^[A-Za-z\s]+$"

    if not re.match(name_regex, name):
        return "Please enter a valid name with alphabets and spaces only."
    
    if not job:
        return "Please select a job."
    
    if not file:
        return "Please choose a file."

    file_extension = file.filename.split('.')[-1]
    if '.' + file_extension.lower() not in valid_extensions:
        return "Please upload a file with a valid extension: pdf or doc."

    if file.content_length > 1024 * 1024:
        return "File size exceeds 1 MB. Please choose a smaller file."
    
    if file.mimetype != 'application/pdf':
        return "Please upload a valid PDF file."
    
    return None

if __name__ == "__main__":
    app.run(debug=True)
