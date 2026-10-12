"""
Flask Web Application for Phishing Email Detector (Objective 7)

Provides:
- Web-based user interface for pasting email text or uploading .eml files
- Interactive results dashboard with color-coded risk indicators
- Plain-language explanations of flagged threats
- Preset sample email loader for instant testing
- Downloadable JSON and printable report views
- RESTful API (/api/analyze) for external integrations
"""

import os
import json
from flask import Flask, render_template, request, jsonify, Response
from werkzeug.utils import secure_filename

from src.pipeline import PhishingDetectorPipeline


def create_app() -> Flask:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static")
    )
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload
    app.config["UPLOAD_EXTENSIONS"] = [".eml", ".txt", ".msg"]

    pipeline = PhishingDetectorPipeline()

    # Preload sample emails for quick testing
    sample_dir = os.path.join(
        os.path.dirname(os.path.dirname(base_dir)),
        "data", "sample_emails"
    )

    sample_cache = {}
    if os.path.exists(sample_dir):
        for fname in os.listdir(sample_dir):
            fpath = os.path.join(sample_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        sample_cache[fname] = f.read()
                except Exception:
                    pass

    @app.route("/", methods=["GET"])
    def index():
        return render_template("index.html", samples=sample_cache)

    @app.route("/analyze", methods=["POST"])
    def analyze():
        raw_text = request.form.get("email_text", "").strip()
        uploaded_file = request.files.get("email_file")

        content = None
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            _, ext = os.path.splitext(filename)
            if ext.lower() not in app.config["UPLOAD_EXTENSIONS"]:
                return render_template(
                    "index.html",
                    error="Invalid file format. Please upload a .eml or .txt file.",
                    samples=sample_cache
                ), 400
            content = uploaded_file.read()
        elif raw_text:
            content = raw_text
        else:
            return render_template(
                "index.html",
                error="Please paste email content or upload an .eml file to analyze.",
                samples=sample_cache
            ), 400

        try:
            result = pipeline.analyze(content)
            return render_template("index.html", result=result, samples=sample_cache)
        except Exception as e:
            return render_template(
                "index.html",
                error=f"Error analyzing email: {str(e)}",
                samples=sample_cache
            ), 500

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        """RESTful API endpoint for analyzing emails programmatically."""
        content = None
        if request.is_json:
            data = request.get_json() or {}
            content = data.get("email_text", "")
        elif "email_file" in request.files:
            file = request.files["email_file"]
            content = file.read()
        elif "email_text" in request.form:
            content = request.form.get("email_text", "")

        if not content:
            return jsonify({
                "status": "error",
                "message": "Missing email content. Provide 'email_text' JSON/form field or 'email_file'."
            }), 400

        try:
            result = pipeline.analyze(content)
            return jsonify({
                "status": "success",
                "data": result
            }), 200
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500

    @app.route("/api/samples/<sample_id>", methods=["GET"])
    def get_sample(sample_id):
        """Fetch sample email content by ID."""
        if sample_id in sample_cache:
            return jsonify({
                "status": "success",
                "sample_id": sample_id,
                "content": sample_cache[sample_id]
            })
        return jsonify({"status": "error", "message": "Sample not found"}), 404

    @app.route("/download/json", methods=["POST"])
    def download_json():
        """Download analysis result as formatted JSON report."""
        raw_result = request.form.get("result_data", "{}")
        try:
            parsed_data = json.loads(raw_result)
            formatted = json.dumps(parsed_data, indent=2)
            return Response(
                formatted,
                mimetype="application/json",
                headers={"Content-Disposition": "attachment;filename=phishing_analysis_report.json"}
            )
        except Exception:
            return Response("{}", mimetype="application/json")

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=5000, debug=True)
