# Flask Repository Analyzer

This project is a Flask-based web application that analyzes GitHub repositories.

## Features
- Accepts a GitHub repository URL as input.
- Analyzes the repository for vulnerabilities, structure, or other attributes.
- Displays the analysis results on the frontend.

## Installation

### Prerequisites
Make sure you have the following installed:
- Python 3.x
- Flask
- Requests (if making API calls)

### Clone the Repository
```bash
git clone https://github.com/Pranavnk15/zero-day-project
cd zero-day-project
```


## Running the Application

### Start the Flask Server
```bash
python app.py
```
The server will start on `http://127.0.0.1:5000/`.

## Usage

1. Open the frontend in a web browser (if applicable).
2. Enter a GitHub repository URL, e.g.,
   ```
   https://github.com/kennethreitz/requests-html
   ```
3. Click "Analyze" to send the request to the Flask backend.
4. View the analysis results.

