import os
import time
import requests
from flask import Flask, render_template, request, jsonify, send_from_directory
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("FLASK_APP_SECRET_KEY")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/anti_phishing.png')
def anti_phishing_image():
    return send_from_directory('templates', 'anti_phishing.png', mimetype='image/png')

@app.route('/image/<filename>')
def serve_image(filename):
    return send_from_directory('static', filename)

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']

    if url == "http://www.example-unsafe-website.com":
        is_safe = False
    else:
        is_safe_google = check_with_google_safe_browsing(url)
        if is_safe_google is None:
            return jsonify({"error": "Error occurred while checking with Google Safe Browsing API"})

        api_key_virustotal = "088351ed8b583f787e208559c864f9767c48e16ce65e28151762350af642bab5"
        analysis = check_virustotal_v2(url, api_key_virustotal)
        if analysis is None:
            return jsonify({"error": "Error occurred while checking with VirusTotal API"})

        malicious = analysis["positives"]
        total_engines = analysis["total"]
        is_safe_virustotal = malicious == 0

        is_safe = is_safe_google and is_safe_virustotal

    print(f"Final result: {'Safe' if is_safe else 'Unsafe'}")
    return jsonify({"is_safe": is_safe})

def check_with_google_safe_browsing(url):
    api_key = 'AIzaSyAdzRiOD-QciHxX8aHLdLV_yGCuL4mjDF8'
    try:
        service = build('safebrowsing', 'v4', developerKey=api_key)
        result = service.threatMatches().find(
            body={
                'client': {'clientId': 'yourcompanyname', 'clientVersion': '1.0'},
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}],
                }
            }
        ).execute()

        if 'matches' in result:
            is_safe = False
        else:
            is_safe = True

        print(f"Google Safe Browsing result: {is_safe}")
        return is_safe

    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

def check_virustotal_v2(url, api_key):
    base_url = "https://www.virustotal.com/vtapi/v2"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.post(
            f"{base_url}/url/scan",
            headers=headers,
            data={"apikey": api_key, "url": url}
        )

        if response.status_code != 200:
            print(f"Error: URL submission failed with status code {response.status_code}")
            return None

        resource = response.json()["resource"]

        time.sleep(5)  # Wait for analysis to complete

        report_response = requests.get(
            f"{base_url}/url/report",
            headers=headers,
            params={"apikey": api_key, "resource": resource, "allinfo": "1"}
        )


        if report_response.status_code != 200:
            print(f"Error: Result request failed with status code {report_response.status_code}")
            return None

        report_json = report_response.json()
        if 'positives' not in report_json:
            print(f"Error: Unexpected response from VirusTotal API during URL analysis: {report_json}")
            return None

        return report_json
    except Exception as e:
        print(f"An error occurred while checking with VirusTotal: {e}")
        return None

if __name__ == '__main__':
    app.run(debug=True)
