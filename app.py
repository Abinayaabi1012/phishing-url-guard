
from flask import Flask, request, jsonify, render_template
from detector import analyze_url
import os
import webbrowser
from threading import Timer

app = Flask(__name__)


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/check")
def check_url():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL to check."}), 400

    try:
        result = analyze_url(url)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "Phishing URL Guard"
    })


if __name__ == "__main__":
    url = "http://127.0.0.1:5000"

    # Open browser automatically only once
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        Timer(
            1.5,
            lambda: webbrowser.open_new(url)
        ).start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
