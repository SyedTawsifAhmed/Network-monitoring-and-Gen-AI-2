from flask import Flask, render_template, request
from risk_qwen import initialize_rag, analyze_config

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    retrieved_examples = []

    if request.method == "POST":
        config_input = request.form.get("config_input", "")

        if config_input.strip():
            output = analyze_config(config_input)
            result = output["assessment"]
            retrieved_examples = output["retrieved_examples"]

    return render_template(
        "index.html",
        result=result,
        retrieved_examples=retrieved_examples
    )

if __name__ == "__main__":
    initialize_rag()
    app.run(host="0.0.0.0", port=5000, debug=True)