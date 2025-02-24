const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// 🔹 Generate 2FA Secret & QR Code
async function generate2FA() {
    const secret = speakeasy.generateSecret({ length: 20 });

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    return { secret: secret.base32, qrCodeUrl };
}

// 🔹 Validate 2FA Code
function validate2FA(token, secret) {
    return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1
    });
}

module.exports = { generate2FA, validate2FA };
