"""
Phishing Email Detector — Web Application Server Runner

Starts the Flask application on http://127.0.0.1:5000.
"""

import sys
from src.web.app import create_app

if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])

    app = create_app()
    print("=" * 60)
    print("Phishing Email Detector Web Interface")
    print(f"Server running at: http://127.0.0.1:{port}")
    print("REST API endpoint: http://127.0.0.1:{port}/api/analyze")
    print("Press Ctrl+C to stop.")
    print("=" * 60)
    app.run(host="127.0.0.1", port=port, debug=False)
