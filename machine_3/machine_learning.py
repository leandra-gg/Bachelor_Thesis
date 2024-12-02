from flask import Flask, request, jsonify
#from google.cloud import storage
import pandas as pd
import joblib

app = Flask(__name__)

# load
# def load_model(bucket_name, model_path):
#     client = storage.Client()
#     bucket = client.bucket(bucket_name)
#     blob = bucket.blob(model_path)
#     blob.download_to_filename("diabetes_model2.pkl")
#     return joblib.load("model.pkl")
@app.route('/analyze', methods=['POST'])
def analyze_data():
    try:
        # get json
        data = request.get_json()
        df = pd.DataFrame(data)

        print("Input for machine 3")
        print(df.head())

        #drop col "Pseudonym" 
        X = df.drop(columns=["Pseudonym"])
        
        #expected features
        feature_columns = ["Pregnancies", "Glucose", "BloodPressure", "SkinThickness", "Insulin", "BMI", "DiabetesPedigreeFunction", "Age"]
        
        # check if features all present
        if not all(col in X.columns for col in feature_columns):
            missing_cols = [col for col in feature_columns if col not in X.columns]
            return jsonify({"error": f"Missing columns for outcome: {missing_cols}"}), 400

        X = X[feature_columns]

        print("Input data")
        print(X.head())

        #load model
        model = joblib.load("/Users/leandra/Desktop/Bachelor_Thesis/Bachelor_Thesis/machine_3/diabetes_model2.pkl")
        print("Loading model was successful.")

        # make predictions
        outcomes = model.predict(X)
        df["Outcome"] = outcomes

        print("Prediction successful:")
        print(df[["Outcome"]].head())

        # response as json
        return jsonify(df.to_dict(orient="records"))

    except Exception as e:
        print(f"Error in analyze_data: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)