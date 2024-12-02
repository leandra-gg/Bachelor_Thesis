from flask import Flask, request, jsonify
import pandas as pd

app = Flask(__name__)

@app.route('/anonymize', methods=['POST'])
def anonymize_data():
    # get json 
    data = request.get_json()
    df = pd.DataFrame(data)

    # remove Patient_ID (anonymization)
    df_anonymized = df.drop(columns=["Patient_ID"])
    
    print(df_anonymized[:10])
    return jsonify(df_anonymized.to_dict(orient="records"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
