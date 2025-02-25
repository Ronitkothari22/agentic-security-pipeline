# agentic-security-pipeline

# Agentic Cybersecurity Pipeline

![Python](https://img.shields.io/badge/Python-3.10-blue.svg) ![Streamlit](https://img.shields.io/badge/Streamlit-1.24.0-red.svg) ![LangGraph](https://img.shields.io/badge/LangGraph-0.0.x-green.svg)


## Overview
The **Agentic Cybersecurity Pipeline** is an automated security assessment tool designed to streamline penetration testing workflows. Built with Python, Streamlit, and LangGraph, this tool integrates popular security utilities such as Nmap, Gobuster, FFUF, and SQLMap, enabling real-time execution and structured reporting.

## Features
- **Scope Enforcement**: Limits scans to predefined domains and IP ranges.
- **Task Management**: Users can select tools and parameters via a UI.
- **Failure Handling**: Implements automated retries for failed scans.
- **Real-Time Execution**: Executes security tools via subprocess.
- **Report Generation**: Outputs findings in JSON format.
- **User Interface**: Streamlit-based dashboard for ease of use.
- **Unit Testing**: Pytest coverage for core functionalities.

## Project Structure
```
agentic-security-pipeline/
├── Logs/                 # Log files directory
├── security_dashboard.py # Streamlit frontend
├── security_pipeline.py  # Core workflow logic
├── test_security_pipeline.py # Unit tests
├── requirements.txt      # Dependencies
└── README.md             # Documentation
```

## Installation
### Prerequisites
- **Python 3.10+**
- **Windows OS** (Tested on Windows 10)
- **Security Tools:** Ensure the following are installed and added to PATH:
  - [Nmap](https://nmap.org/download.html)
  - [Gobuster](https://github.com/OJ/gobuster/releases)
  - [FFUF](https://github.com/ffuf/ffuf/releases)
  - [SQLMap](https://github.com/sqlmapproject/sqlmap.git)
  - Wordlists (e.g., `common.txt` from [SecLists](https://github.com/danielmiessler/SecLists))

### Setup
```bash
git clone https://github.com/yourusername/agentic-security-pipeline.git
cd agentic-security-pipeline
python -m venv venv
source venv/bin/activate  # (Windows: venv\Scripts\activate)
pip install -r requirements.txt
```

## Usage
```bash
streamlit run security_dashboard.py
```
- Open `http://localhost:8501`
- Configure scope (allowed domains and IPs)
- Add tasks (e.g., Nmap scan on `google.com`)
- Execute the pipeline and review results

## Testing
Run unit tests:
```bash
pytest test_security_pipeline.py -v
```


