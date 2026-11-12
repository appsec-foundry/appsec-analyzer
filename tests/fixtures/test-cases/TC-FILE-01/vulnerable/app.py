import os

from flask import Flask, request, send_file

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.get("/api/reports/download")
def download_report():
    name = request.args.get("name", "")
    return send_file(os.path.join(REPORTS, name))
