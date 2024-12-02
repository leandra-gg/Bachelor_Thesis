import requests
import json
import pandas as pd

#machine url(lokal)
MACHINE1_URL = "http://127.0.0.1:8080/process"
MACHINE2_URL = "http://127.0.0.1:8081/anonymize"
MACHINE3_URL = "http://127.0.0.1:8082/analyze"
MACHINE4_URL = "http://127.0.0.1:8083/decision"

def orchestrate_workflow(file_path):
    #first step: load dataset
    print("Load dataset...")
    df = pd.read_csv(file_path)
    data = df.to_dict(orient="records")

    #check original data
    print("original data:")
    print(df.head())

    #step 2: send to machine 1 
    print("send data to machine 1...")
    response1 = requests.post(MACHINE1_URL, json=data)
    machine1_output = response1.json()
    print("Machine 1 - output:")
    print(json.dumps(machine1_output[:2], indent=4)) 

    #step 3: send to machine 2
    print("send data to machine 2...")
    response2 = requests.post(MACHINE2_URL, json=machine1_output)
    machine2_output = response2.json()
    print("machine 2 - outcome:")
    print(json.dumps(machine2_output[:2], indent=4))

    #step 4: send to machine 3
    print("send data to machine 3...")
    response3 = requests.post(MACHINE3_URL, json=machine2_output)
    response3 = requests.post(MACHINE3_URL, json=machine2_output)
    machine3_output = response3.json()
    print("machine 3 - outcome:")
    print(json.dumps(machine3_output[:2], indent=4))

    #step 5: send to machine 4 
    print("send data to machine 4...")
    response4 = requests.post(MACHINE4_URL, json=machine3_output)
    machine4_output = response4.json()
    print("Maschine 4 - output:")
    print(json.dumps(machine4_output[:2], indent=4))

    # step 6: results back to machine 1
    print("send final results back to machine 1")
    final_response = requests.post(MACHINE1_URL, json=machine4_output)
    final_results = final_response.json()
    print("Finale Ergebnisse:")
    print(json.dumps(final_results,indent=4))

    return final_results

if __name__ == "__main__":
    #path csv file
    file_path = "/Users/leandra/Downloads/dataset_10.csv"

    #start workflow
    results = orchestrate_workflow(file_path)
    print("Workflow successfully completed. Final results:")
    print(json.dumps(results, indent=4))
