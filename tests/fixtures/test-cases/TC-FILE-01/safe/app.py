from flask import Flask, request, send_from_directory

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.get("/api/reports/download")
def download_report():
    name = request.args.get("name", "")
    return send_from_directory(REPORTS, name)
