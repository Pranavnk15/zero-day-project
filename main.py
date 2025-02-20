from flask import Flask, render_template, request, jsonify
import os
import requests
import subprocess
from pathlib import Path
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config["TEMPLATES_AUTO_RELOAD"] = False

# GitHub API details
GITHUB_API_URL = "https://api.github.com/repos"
GITHUB_TOKEN = ""  # Replace with your GitHub token

def fetch_repo_contents(repo_url, path=""):
    """
    Fetch the contents of a GitHub repository recursively.
    """
    parts = repo_url.strip("/").split("/")
    owner, repo = parts[-2], parts[-1]

    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    contents_url = f"{GITHUB_API_URL}/{owner}/{repo}/contents/{path}"
    response = requests.get(contents_url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to fetch repository contents: {response.status_code}")

    contents = response.json()
    files = []

    for item in contents:
        if item["type"] == "file" and item["name"].endswith(".py"):
            files.append(item)
        elif item["type"] == "dir":
            files.extend(fetch_repo_contents(repo_url, item["path"]))

    return files

def download_files(contents, output_dir="repo_files"):
    """
    Download files from the repository, preserving directory structure.
    """
    Path(output_dir).mkdir(exist_ok=True)
    downloaded_files = []

    for item in contents:
        file_path = Path(output_dir) / item["path"]
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "wb") as f:
            file_content = requests.get(item["download_url"]).content
            f.write(file_content)
        downloaded_files.append(file_path)

    return downloaded_files

def analyze_code_for_vulnerabilities(file_paths):
    """
    Analyze the downloaded code for vulnerabilities using Bandit.
    """
    results = []
    for file_path in file_paths:
        print(f"Analyzing file: {file_path}")
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            results.append(f"File not found: {file_path}")
            continue
        try:
            result = subprocess.run(
                ["bandit", "-r", str(file_path)],
                capture_output=True,
                text=True
            )
            print(f"Bandit stdout: {result.stdout}")
            print(f"Bandit stderr: {result.stderr}")

            # Check if Bandit produced output (even if it found issues)
            if result.stdout:
                results.append(result.stdout)
            else:
                # If no output, log the error
                results.append(f"Bandit failed for {file_path}: {result.stderr}")
        except Exception as e:
            print(f"Error running Bandit on {file_path}: {e}")
            results.append(f"Error running Bandit on {file_path}: {e}")
    return results

def generate_report(analysis_results):
    """
    Generate a report from the analysis results.
    """
    report = "Vulnerability Analysis Report:\n\n"
    for i, result in enumerate(analysis_results):
        report += f"File {i + 1}:\n{result}\n\n"
    return report

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        repo_url = request.form.get("repo_url")
        print(f"Received repository URL: {repo_url}")
        if not repo_url:
            return jsonify({"error": "Please provide a GitHub repository URL."}), 400

        try:
            # Step 1: Fetch repository contents
            contents = fetch_repo_contents(repo_url)
            print(f"Fetched contents: {contents}")

            # Step 2: Download files
            downloaded_files = download_files(contents)
            print(f"Downloaded files: {downloaded_files}")

            if not downloaded_files:
                return jsonify({"error": "No Python files found in the repository."}), 404

            # Step 3: Analyze code for vulnerabilities
            analysis_results = analyze_code_for_vulnerabilities(downloaded_files)
            print(f"Analysis results: {analysis_results}")

            # Step 4: Generate a report
            report = generate_report(analysis_results)
            return jsonify({"report": report})

        except Exception as e:
            print(f"Error: {e}")
            return jsonify({"error": f"An error occurred: {e}"}), 500

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False, threaded=True)
