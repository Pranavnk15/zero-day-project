from flask import Flask, render_template, request, jsonify
import os
import requests
import subprocess
from pathlib import Path

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = False

# GitHub API details
GITHUB_API_URL = "https://api.github.com/repos"
GITHUB_TOKEN = "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"  # Replace with your GitHub token


def fetch_repo_contents(repo_url, path=""):
    """
    Fetch the contents of a GitHub repository recursively.
    """
    # Extract owner and repo name from the URL
    parts = repo_url.strip("/").split("/")
    owner, repo = parts[-2], parts[-1]

    # Fetch repository contents
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
            # Recursively fetch contents of subdirectories
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
        file_path.parent.mkdir(parents=True, exist_ok=True)  # Create parent directories
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
        print(f"Analyzing file: {file_path}")  # Log the file being analyzed
        result = subprocess.run(
            ["bandit", "-r", str(file_path)],
            capture_output=True,
            text=True
        )
        results.append(result.stdout)
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
        print(f"Received repository URL: {repo_url}")  # Log the URL
        if not repo_url:
            return jsonify({"error": "Please provide a GitHub repository URL."})

        try:
            # Step 1: Fetch repository contents
            contents = fetch_repo_contents(repo_url)
            print(f"Fetched contents: {contents}")  # Log the fetched contents

            # Step 2: Download files
            downloaded_files = download_files(contents)
            print(f"Downloaded files: {downloaded_files}")  # Log the downloaded files

            if not downloaded_files:
                return jsonify({"error": "No Python files found in the repository."})

            # Step 3: Analyze code for vulnerabilities
            analysis_results = analyze_code_for_vulnerabilities(downloaded_files)
            print(f"Analysis results: {analysis_results}")  # Log the analysis results

            # Step 4: Generate a report
            report = generate_report(analysis_results)
            return jsonify({"report": report})

        except Exception as e:
            print(f"Error: {e}")  # Log the error
            return jsonify({"error": f"An error occurred: {e}"})

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)