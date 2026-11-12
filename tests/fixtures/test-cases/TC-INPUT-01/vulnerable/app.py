import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/api/products")
def search_products():
    term = request.args.get("q", "")
    with sqlite3.connect("shop.db") as db:
        rows = db.execute(f"SELECT id, name FROM products WHERE name LIKE '%{term}%'").fetchall()
    return jsonify(rows)
