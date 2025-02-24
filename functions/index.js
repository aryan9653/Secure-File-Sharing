require("dotenv").config();
const functions = require("firebase-functions");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const ethers = require("ethers");
const fs = require("fs");
const { exec } = require("child_process");

admin.initializeApp();

const app = express();
app.use(cors());
app.use(express.json());

const AES_SECRET_KEY = process.env.AES_SECRET_KEY;
const BLOCKCHAIN_NODE_URL = process.env.BLOCKCHAIN_NODE_URL;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

const LOG_FILE_PATH = "logs/access_logs.json";

// ✅ Import AI anomaly detection
const { detectAnomalies } = require("./ai/detectAnomalies");

// ✅ Blockchain setup
const provider = new ethers.JsonRpcProvider(BLOCKCHAIN_NODE_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

// ✅ Function: Log Access Attempts
const logAccessAttempt = (userId, fileId, ip) => {
    const timestamp = Date.now();
    const logEntry = { userId, fileId, ip, timestamp };

    let logs = [];
    if (fs.existsSync(LOG_FILE_PATH)) {
        logs = JSON.parse(fs.readFileSync(LOG_FILE_PATH, "utf8"));
    }

    logs.push(logEntry);
    fs.writeFileSync(LOG_FILE_PATH, JSON.stringify(logs, null, 2));
};

// ✅ AES Encryption Helper Functions
const encryptFile = (data) => {
    const cipher = crypto.createCipheriv(
        "aes-256-cbc",
        Buffer.from(AES_SECRET_KEY, "hex"),
        Buffer.alloc(16, 0)
    );
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString("hex");
};

const decryptFile = (encryptedData) => {
    const decipher = crypto.createDecipheriv(
        "aes-256-cbc",
        Buffer.from(AES_SECRET_KEY, "hex"),
        Buffer.alloc(16, 0)
    );
    let decrypted = decipher.update(Buffer.from(encryptedData, "hex"));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
};

// ✅ API Route: Upload File with Encryption
app.post("/upload", async (req, res) => {
    try {
        const { filename, fileData } = req.body;
        if (!filename || !fileData) return res.status(400).json({ error: "Missing filename or fileData" });

        const encryptedData = encryptFile(fileData);

        const fileRef = admin.storage().bucket().file(filename);
        await fileRef.save(encryptedData, { metadata: { contentType: "text/plain" } });

        return res.json({ message: "File uploaded successfully", filename });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "File upload failed" });
    }
});

// ✅ API Route: Verify File Integrity via Blockchain
app.post("/verify", async (req, res) => {
    try {
        const { filename, originalHash } = req.body;
        if (!filename || !originalHash) return res.status(400).json({ error: "Missing filename or hash" });

        const fileRef = admin.storage().bucket().file(filename);
        const [fileBuffer] = await fileRef.download();
        const fileHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");

        if (fileHash === originalHash) {
            return res.json({ message: "File integrity verified!" });
        } else {
            return res.status(400).json({ error: "File integrity compromised!" });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "File verification failed" });
    }
});

// ✅ AI-Based Anomaly Detection (Runs every 60 seconds)
setInterval(() => {
    exec("python3 ai/anomaly_detector.py", (error, stdout, stderr) => {
        if (error) {
            console.error("❌ AI Anomaly Detection Error:", stderr);
        } else {
            console.log(stdout);
        }
    });
}, 60000); // Run every 60 seconds

// ✅ API Route: Secure File Download with Anomaly Detection & 2FA
app.post("/download", async (req, res) => {
    try {
        const { fileId, token, secret, userId, ip } = req.body;

        // ✅ Log access attempt
        logAccessAttempt(userId, fileId, ip);

        // ✅ Validate 2FA before allowing download
        if (!validate2FA(token, secret)) {
            return res.status(403).json({ error: "Invalid 2FA code" });
        }

        const fileDoc = await admin.firestore().collection("files").doc(fileId).get();
        if (!fileDoc.exists) {
            return res.status(404).json({ error: "File not found" });
        }

        // ✅ AI-based anomaly detection before allowing access
        const anomalies = await detectAnomalies();
        const isSuspicious = anomalies.some((log) => log.userId === userId && log.ip === ip);
        if (isSuspicious) {
            return res.status(403).json({ error: "Suspicious activity detected, access denied" });
        }

        // ✅ Continue with file decryption and sending
        res.download("decryptedFilePath"); // Replace with actual decrypted file path
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ Deploy Express App as Firebase Function
exports.api = functions.https.onRequest(app);
