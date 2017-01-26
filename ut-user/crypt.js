const crypto = require('crypto');

/*
    Used as memory to store dectypted passwords, in order to reduce
    decrypting proccess for same password over and over again
*/
var cachedDecryptedPasswords = {};

function getDefaultCryptParams() {
    return {
        algorithm: 'aes192',
        dataEnc: 'utf8',
        encryptedEnc: 'hex'
    };
}

function UtCrypt(opts) {
    if (!(this instanceof UtCrypt)) {
        return new UtCrypt(opts);
    }

    this.key = opts.key;
    this.cryptParams = Object.assign({}, getDefaultCryptParams(), opts.cryptParams || {});
}

UtCrypt.prototype.decrypt = function(data, cryptParams) {
    var cryptKey = JSON.stringify(cryptParams);
    if (cachedDecryptedPasswords[cryptKey] && cachedDecryptedPasswords[cryptKey][data]) {
        return cachedDecryptedPasswords[cryptKey][data];
    } else {
        var cp = cryptParams || this.cryptParams;
        var decipher = crypto.createDecipher(cp.algorithm, cp.password);
        var decrypted = decipher.update(data, cp.encryptedEnc, cp.dataEnc);
        decrypted += decipher.final(cp.dataEnc);

        // Save the decrypted password in cache
        if (!cachedDecryptedPasswords[cryptKey]) { // ecnrypt may produce same cryptData with different crypArg
            cachedDecryptedPasswords[cryptKey] = {};
        }
        cachedDecryptedPasswords[cryptKey][data] = decrypted;

        return decrypted;
    }
};

UtCrypt.prototype.getDefaultCryptParams = getDefaultCryptParams;

module.exports = UtCrypt;
