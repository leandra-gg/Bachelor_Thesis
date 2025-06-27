import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score


def train_model(model_local_path="diabetes_model2.pkl"):
    training_data=pd.read_csv("/Users/leandra/Desktop/Bachelor_Thesis/Bachelor_Thesis/machine_1/diabetes.csv")
    X=training_data.drop(columns=["Outcome"])
    y=training_data["Outcome"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    #train model
    model=RandomForestClassifier()
    model.fit(X_train,y_train)

    predictions=model.predict(X_test)
    accuracy=accuracy_score(y_test,predictions)
    print(f"Model Accuracy: {accuracy:.2f}")

    joblib.dump(model, model_local_path)
    print(f"Model saved locally as {model_local_path}")

train_model()