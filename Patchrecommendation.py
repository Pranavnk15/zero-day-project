from flask import Flask, render_template, request, jsonify
import os
import requests
import subprocess
from pathlib import Path
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config["TEMPLATES_AUTO_RELOAD"] = False
GITHUB_API_URL = "https://api.github.com/repos"
GITHUB_TOKEN = "ghp_YOUR_GITHUB_TOKEN"  # Replace with your GitHub token

# Global memory to store vulnerabilities and their patches
vulnerability_memory = {}

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

def get_patch_recommendation(vulnerability_description):
    """
    Generate a patch recommendation for a given vulnerability using a rule-based approach.
    """
    global vulnerability_memory

    # Check if the vulnerability is already in memory
    if vulnerability_description in vulnerability_memory:
        print("Reusing patch from memory.")
        return vulnerability_memory[vulnerability_description]

    # Rule-based patch recommendations
    if "SQL injection" in vulnerability_description:
        patch_recommendation = """
        To prevent SQL injection, use parameterized queries or prepared statements.
        Example:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        """
    elif "hardcoded password" in vulnerability_description:
        patch_recommendation = """
        Avoid hardcoding passwords in the code. Use environment variables or a secure vault.
        Example:
        import os
        password = os.getenv('DB_PASSWORD')
        """
    elif "use of insecure hash function" in vulnerability_description:
        patch_recommendation = """
        Use a secure hash function like bcrypt or Argon2 instead of MD5 or SHA1.
        Example:
        import bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        """
    elif "insecure deserialization" in vulnerability_description:
        patch_recommendation = """
        Avoid deserializing untrusted data. Use safer serialization formats like JSON.
        Example:
        import json
        data = json.loads(trusted_data)
        """
    else:
        patch_recommendation = """
        No specific patch recommendation available. Review the code and follow secure coding practices.
        """

    # Store the vulnerability and patch in memory
    vulnerability_memory[vulnerability_description] = patch_recommendation
    return patch_recommendation

def analyze_code_for_vulnerabilities(file_paths):
    """
    Analyze the downloaded code for vulnerabilities using Bandit and generate patch recommendations.
    """
    results = []
    for file_path in file_paths:
        print(f"Analyzing file: {file_path}")
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            results.append({"file": file_path, "error": "File not found"})
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
                # Generate patch recommendations for each vulnerability
                patch_recommendations = get_patch_recommendation(result.stdout)
                results.append({
                    "file": file_path,
                    "vulnerabilities": result.stdout,
                    "patch_recommendations": patch_recommendations
                })
            else:
                # If no output, log the error
                results.append({
                    "file": file_path,
                    "error": f"Bandit failed: {result.stderr}"
                })
        except Exception as e:
            print(f"Error running Bandit on {file_path}: {e}")
            results.append({
                "file": file_path,
                "error": f"Error running Bandit: {e}"
            })
    return results

def generate_report(analysis_results):
    """
    Generate a report from the analysis results, including vulnerabilities and patch recommendations.
    """
    report = "Vulnerability Analysis Report:\n\n"
    for i, result in enumerate(analysis_results):
        report += f"File {i + 1}: {result.get('file')}\n"
        if "error" in result:
            report += f"Error: {result['error']}\n\n"
        else:
            report += f"Vulnerabilities:\n{result['vulnerabilities']}\n"
            report += f"Patch Recommendations:\n{result['patch_recommendations']}\n\n"
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