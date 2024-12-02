from flask import Flask, request, jsonify
import pandas as pd

app = Flask(__name__)

@app.route('/decision', methods=['POST'])
def make_decision():
    #data as json
    data = request.get_json()
    df = pd.DataFrame(data)

    #suggest decision based on prediction/outcome
    if "Outcome" in df.columns:
        df["Risk_Level"] = df["Outcome"].apply(lambda x: "High Risk" if x == 1 else "Low Risk")
    else:
        return jsonify({"error": "Outcome column missing"}), 400

    return jsonify(df.to_dict(orient="records"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8083)
