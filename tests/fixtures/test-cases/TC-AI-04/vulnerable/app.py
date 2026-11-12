import chromadb
from flask import Flask, jsonify, request
from flask_login import current_user, login_required
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()
notes = chromadb.PersistentClient(path="vectors").get_collection("notes")


@app.post("/api/ask")
@login_required
def ask():
    question = request.json["question"]
    found = notes.query(query_texts=[question], n_results=5)
    context = "\n".join(found["documents"][0])
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Answer from these notes:\n" + context},
            {"role": "user", "content": question},
        ],
    )
    return jsonify(answer=reply.choices[0].message.content, user=current_user.id)
