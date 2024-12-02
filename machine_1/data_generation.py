from flask import Flask, request, jsonify
import pandas as pd
import uuid

app = Flask(__name__)

@app.route('/process', methods=['POST'])
def process_data():
    data = request.get_json()
    df = pd.DataFrame(data)

    # add Patient_ID und Pseudonym 
    if "Patient_ID" not in df.columns and "Pseudonym" not in df.columns:
        df["Patient_ID"] = [uuid.uuid4().hex for _ in range(len(df))]
        df["Pseudonym"] = [f'Patient_{uuid.uuid4().hex[:8]}' for _ in range(len(df))]

    # clean data
    df_cleaned = df.dropna()

    return jsonify(df_cleaned.to_dict(orient="records"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
