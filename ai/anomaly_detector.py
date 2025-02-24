import json
import numpy as np
from sklearn.ensemble import IsolationForest

# Load access logs
try:
    with open("logs/access_logs.json", "r") as file:
        data = json.load(file)
except FileNotFoundError:
    print("[]")  # Return an empty list if no logs exist
    exit(0)

if not data:
    print("[]")
    exit(0)

# Extract features (timestamps & hashed IPs)
X = np.array([[entry["timestamp"], hash(entry["ip"]) % 1000] for entry in data])

# Train Isolation Forest Model
model = IsolationForest(contamination=0.1)
model.fit(X)

# Predict anomalies
anomalies = model.predict(X)

# Filter suspicious activities
suspicious_activities = [data[i] for i in range(len(data)) if anomalies[i] == -1]

# Output detected anomalies as JSON
print(json.dumps(suspicious_activities))
