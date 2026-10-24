# Phishing URL Guard — runnable prototype

A polished web UI + JSON API for checking URLs against common phishing patterns. It is designed as a beginner-friendly prototype that can run locally and can be adapted to AWS Lambda + API Gateway + S3.

## Important accuracy note
This is a **pattern-based screening prototype**, not a trained ML model and not a production security product. It does not visit the URL, use live threat-intelligence feeds, or guarantee that a result marked low risk is safe. A real ML version needs a reputable, labelled URL dataset, a reproducible training/evaluation pipeline, and ongoing model monitoring. Do not use this prototype to make high-stakes security decisions.

## Run locally (Windows)
1. Install Python 3.10 or newer from https://www.python.org/downloads/ and enable **Add Python to PATH**.
2. Extract the ZIP folder.
3. Open Command Prompt in the extracted `phishing_url_guard` folder.
4. Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
5. Install dependencies:
   ```bat
   python -m pip install -r requirements.txt
   ```
6. Start the app:
   ```bat
   python app.py
   ```
7. Open http://127.0.0.1:5000 in your browser.
8. Try examples:
   - `https://www.wikipedia.org` — expected low-risk pattern result
   - `http://secure-account-verify.example.com/login` — expected elevated warning signals
   These are illustrative tests only, not ground-truth labels.

Stop the server with `Ctrl+C`.

## API test
With the server running, open another Command Prompt:
```bat
curl -X POST http://127.0.0.1:5000/api/check -H "Content-Type: application/json" -d "{\"url\":\"http://secure-account-verify.example.com/login\"}"
```
Health check: open `http://127.0.0.1:5000/health`.

## Project structure
- `app.py` — local Flask server and API endpoint
- `detector.py` — URL parsing and explainable risk signals
- `templates/index.html` — responsive interface
- `lambda_function.py` — AWS Lambda handler for API Gateway proxy events

## AWS deployment outline (Lambda + API Gateway + S3)
This starter has the Lambda handler, but the static UI is served by Flask locally. For a cloud deployment:
1. Create an S3 bucket for the static website assets. Keep **Block Public Access enabled** unless you intentionally configure a secure public delivery method; prefer CloudFront with Origin Access Control for production.
2. Upload a static `index.html` version to S3. Change its API call from relative `/api/check` to your deployed API Gateway endpoint, and configure CORS on API Gateway for the exact website origin.
3. Package `lambda_function.py` and `detector.py` in a ZIP. Since these files use only Python standard-library modules, no third-party Lambda dependencies are needed.
4. Create a Lambda function using a compatible Python runtime, handler `lambda_function.lambda_handler`, and upload the ZIP.
5. Create an API Gateway HTTP API with a `POST /api/check` route and a `GET /health` route, integrated with Lambda. Enable CORS for your S3/CloudFront website origin and `content-type`.
6. Deploy the API stage, then test the endpoint with:
   ```bash
   curl -X POST "YOUR_API_ENDPOINT/api/check" -H "Content-Type: application/json" -d '{"url":"https://example.com"}'
   ```
7. Do not store submitted URLs unless there is a clear need and privacy policy. Add rate limits, logging redaction, monitoring, abuse protection, and security review before public release.

AWS console labels can change. Follow current AWS documentation for exact screens and permissions. Never put AWS access keys in frontend code.

## Suggested next steps for a real ML project
- Use a lawful, well-documented, labelled phishing/benign URL dataset.
- Split by domain/time to reduce leakage; train and compare a baseline (e.g., logistic regression or gradient boosting).
- Evaluate precision, recall, F1, false-positive rate, and calibration; phishing false negatives matter.
- Save the trained model and feature pipeline together, version them, test against fresh data, and monitor drift.
- Add a reputable threat-intelligence lookup only after reviewing its privacy, terms, cost, and rate limits.
