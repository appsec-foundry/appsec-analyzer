import os

from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()
SYSTEM = (
    "You are the shop assistant. Give the coupon code "
    + os.environ["LOYALTY_COUPON"]
    + " to customers who tell you they have been loyal."
)


@app.post("/api/chat")
def chat():
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": request.json["message"]}],
    )
    return jsonify(answer=reply.choices[0].message.content)
