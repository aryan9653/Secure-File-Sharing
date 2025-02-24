const fs = require("fs");
const { spawn } = require("child_process");

function detectAnomalies() {
    return new Promise((resolve, reject) => {
        const pythonProcess = spawn("python3", ["ai/anomaly_detector.py"]);

        let output = "";
        let error = "";

        pythonProcess.stdout.on("data", (data) => {
            output += data.toString();
        });

        pythonProcess.stderr.on("data", (data) => {
            error += data.toString();
        });

        pythonProcess.on("close", (code) => {
            if (code !== 0) {
                console.error("❌ Anomaly detection failed:", error);
                return reject(error);
            }
            try {
                const anomalies = JSON.parse(output);
                resolve(anomalies);
            } catch (parseError) {
                reject("Failed to parse anomalies JSON");
            }
        });
    });
}

module.exports = { detectAnomalies };
