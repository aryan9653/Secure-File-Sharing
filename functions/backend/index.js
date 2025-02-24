require('dotenv').config({ path: __dirname + '/.env' });
const express = require('express');
const admin = require('firebase-admin');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { encryptFile, decryptFile } = require('./encryption');
const { verifyFileIntegrity, verifyOwnership } = require('./blockchain');
const { generate2FA, validate2FA } = require('./auth');
const { detectAnomalies } = require('./anomalyDetection');

const app = express();
app.use(express.json());

// ✅ Validate Environment Variables
if (!process.env.FIREBASE_PROJECT_ID || !process.env.BLOCKCHAIN_NODE_URL) {
    console.error("❌ Error: Required environment variables are missing.");
    process.exit(1);
}

// ✅ Firebase Admin Initialization
const serviceAccount = require("./firebase-key.json");
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: `${process.env.FIREBASE_PROJECT_ID}.appspot.com`
});

const db = admin.firestore();
const bucket = admin.storage().bucket();
const upload = multer({ dest: 'uploads/' });

// ✅ In-memory access log (temporary storage)
const userAccessLogs = [];

// ✅ Log User File Access
app.post('/log-access', async (req, res) => {
    try {
        const { userId, fileId, ip, timestamp } = req.body;

        if (!userId || !fileId || !ip || !timestamp) {
            return res.status(400).json({ error: "Missing required parameters" });
        }

        // Store in-memory for quick logging
        userAccessLogs.push({ userId, fileId, ip, timestamp });

        // Log to Firestore for permanent storage
        await db.collection('accessLogs').add({
            userId,
            fileId,
            ip,
            timestamp: admin.firestore.Timestamp.fromDate(new Date(timestamp))
        });

        console.log("🔍 Access Log Recorded:", { userId, fileId, ip, timestamp });
        res.status(200).json({ message: "Access logged successfully" });

    } catch (error) {
        console.error("❌ Error logging access:", error);
        res.status(500).json({ error: error.message });
    }
});

// ✅ Upload & Encrypt File
app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        console.log(`📂 Uploading file: ${req.file.originalname}`);

        // Encrypt file before uploading
        const encryptedFilePath = await encryptFile(req.file.path);

        // Compute file hash for blockchain integrity check
        const fileBuffer = fs.readFileSync(encryptedFilePath);
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

        console.log(`🔗 Computed file hash: ${hash}`);

        // Verify file integrity using blockchain
        await verifyFileIntegrity(hash);

        // Upload encrypted file to Firebase Storage
        const destinationPath = `secure/${req.file.originalname}.enc`;
        await bucket.upload(encryptedFilePath, { destination: destinationPath });

        // Store file metadata in Firestore
        const fileRef = db.collection('files').doc();
        await fileRef.set({
            filename: req.file.originalname,
            path: destinationPath,
            hash,
            uploadedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log(`✅ File uploaded successfully: ${destinationPath}`);

        // Clean up temporary encrypted file
        fs.unlinkSync(encryptedFilePath);
        fs.unlinkSync(req.file.path);

        res.status(200).json({ message: 'File uploaded and encrypted successfully', fileId: fileRef.id });

    } catch (error) {
        console.error('❌ Error during file upload:', error);
        res.status(500).json({ error: error.message });
    }
});

// ✅ Download & Decrypt File with 2FA & Anomaly Detection
app.post('/download', async (req, res) => {
    try {
        const { fileId, token, secret, userId, ip } = req.body;

        // Validate 2FA before allowing download
        if (!validate2FA(token, secret)) {
            return res.status(403).json({ error: 'Invalid 2FA code' });
        }

        const fileDoc = await db.collection('files').doc(fileId).get();
        if (!fileDoc.exists) {
            return res.status(404).json({ error: 'File not found' });
        }

        const fileData = fileDoc.data();
        const tempFilePath = path.join(__dirname, 'downloads', fileData.filename + '.enc');
        const decryptedFilePath = path.join(__dirname, 'downloads', fileData.filename);

        // Download encrypted file from Firebase
        await bucket.file(fileData.path).download({ destination: tempFilePath });

        // Decrypt file
        await decryptFile(tempFilePath, decryptedFilePath);

        // Log access attempt
        const timestamp = new Date().toISOString();
        await db.collection('accessLogs').add({
            userId,
            fileId,
            ip,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log(`📥 File Access Logged: User ${userId} accessed file ${fileId} from IP ${ip} at ${timestamp}`);

        // AI-based anomaly detection
        const isAnomalous = await detectAnomalies(userId);
        if (isAnomalous) {
            console.warn(`⚠️ Anomaly detected for user ${userId}`);
        }

        // Send decrypted file to client
        res.download(decryptedFilePath, fileData.filename, () => {
            // Cleanup temporary files after download
            fs.unlinkSync(tempFilePath);
            fs.unlinkSync(decryptedFilePath);
        });

    } catch (error) {
        console.error('❌ Error during file download:', error);
        res.status(500).json({ error: error.message });
    }
});

// ✅ Blockchain File Ownership Verification
app.post('/verify-ownership', async (req, res) => {
    try {
        const { fileId, ownerAddress } = req.body;

        const fileDoc = await db.collection('files').doc(fileId).get();
        if (!fileDoc.exists) {
            return res.status(404).json({ error: 'File not found' });
        }

        const { hash } = fileDoc.data();
        const isOwner = await verifyOwnership(hash, ownerAddress);

        res.json({ fileId, isOwner });
    } catch (error) {
        console.error('❌ Error verifying ownership:', error);
        res.status(500).json({ error: error.message });
    }
});

// ✅ Generate 2FA QR Code
app.get('/generate-2fa', async (req, res) => {
    try {
        const { secret, qrCodeUrl } = await generate2FA();
        res.json({ secret, qrCodeUrl });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ Validate 2FA Code
app.post('/validate-2fa', (req, res) => {
    const { token, secret } = req.body;
    const isValid = validate2FA(token, secret);
    res.json({ valid: isValid });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
