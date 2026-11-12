from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()
SYSTEM = "You are the shop assistant. You cannot grant discounts; the checkout applies the ones a customer has earned."


@app.post("/api/chat")
def chat():
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": request.json["message"]}],
    )
    return jsonify(answer=reply.choices[0].message.content)
