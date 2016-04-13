var errors = require('../errors');
var crypto = require('crypto');
var when = require('when');

function getHash(password, hashInfo) {
    if (!hashInfo || !hashInfo.params) {
        return false;
    }
    hashInfo.params = JSON.parse(hashInfo.params);
    return when.promise(function(resolve) {
        switch (hashInfo.algorithm) {
            case 'pbkdf2':
                crypto.pbkdf2(password, hashInfo.params.salt, hashInfo.params.iterations, hashInfo.params.keylen, hashInfo.params.digest, (err, key) => {
                    if (err) {
                        return errors.crypt.reject();
                    }
                    resolve(key.toString('hex'));
                });
                break;
        }
    });
}

module.exports = {
    'check': function(msg, $meta) {
        msg.type = '';
        if (typeof (msg.username) !== 'undefined' && typeof (msg.password) !== 'undefined') {
            msg.type = 'user/pass';
        } else if (typeof (msg.fingerPrint) !== 'undefined') {
            msg.type = 'bio';
        } else if (typeof (msg.token) !== 'undefined') { // session
            msg.type = 'session';
        } else {
            return errors.MissingCredentials.reject();
        }

        return this.bus.importMethod('user.identity.getHashParams')(msg, $meta)
        .then((res) => {
            if (res[0].length > 1) {
                return errors.multipleResults.reject();
            }
            return getHash(msg.password, res[0][0]);
        })
        .then((res) => {
            msg.password = res;
            return this.bus.importMethod('user.identity.check')(msg, $meta);
        })
        .then((res) => {
            if (res[0] && res[0][0] && res[0][0].actorId) {
                return this.bus.importMethod('permission.get')(res[0][0].actorId, $meta);
            }
            return res;
        });
    }
};
