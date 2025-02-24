const fs = require('fs');
const crypto = require('crypto');
const AES_SECRET_KEY = process.env.AES_SECRET_KEY;

function encryptFile(filePath) {
    const cipher = crypto.createCipher('aes-256-cbc', AES_SECRET_KEY);
    const input = fs.createReadStream(filePath);
    const output = fs.createWriteStream(`${filePath}.enc`);

    input.pipe(cipher).pipe(output);
    return `${filePath}.enc`;
}

function decryptFile(encryptedFilePath) {
    const decipher = crypto.createDecipher('aes-256-cbc', AES_SECRET_KEY);
    const input = fs.createReadStream(encryptedFilePath);
    const output = fs.createWriteStream(encryptedFilePath.replace('.enc', ''));

    input.pipe(decipher).pipe(output);
    return encryptedFilePath.replace('.enc', '');
}

module.exports = { encryptFile, decryptFile };
