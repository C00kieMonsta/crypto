//
// CRYPTO Library from NodeJS
//

const crypto = require('crypto');
const algorithm = 'aes-192-cbc';
const password = '8f17a3ca-fdd0-43b4-8fbc-3a0904c51a56';
const key = crypto.scryptSync(password, 'salt', 24);

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(text, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

function hashPassword(password) {
    const nowInMinutesRounded = Math.round(Date.now() / 1000000) * 1000;
    const hash = crypto.createHmac('sha256', `${password}.${nowInMinutesRounded}`).digest('hex');
    return hash;
}

var hw = encrypt('fx63N4beZEQlPCEC3PM2uCcSXjrVZ-P4EKnqrbkC9M86SoA6jSdb-t0GPlejjKWG');
console.log(hw);
console.log(decrypt(hw));

const hashedPassword = hashPassword('fx63N4beZEQlPCEC3PM2uCcSXjrVZ-P4EKnqrbkC9M86SoA6jSdb-t0GPlejjKWG');
console.log(hashedPassword);

//
// CRYPTO-JS Library
//
const cryptoJS = require('crypto-js');

function encryptCryptoJS(text) {
    const encryptedMetaData = cryptoJS.AES.encrypt(text, 'AESSecretKey').toString();
    return encryptedMetaData;
}

function decryptCryptoJS(text) {
    const decipheredData = cryptoJS.AES.decrypt(text, 'AESSecretKey').toString(cryptoJS.enc.Utf8);
    return decipheredData;
}
