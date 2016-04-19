var errors = require('../errors');
var crypto = require('crypto');

function getHash(password, hashInfo) {
    if (!hashInfo || !hashInfo.params) {
        return errors.InvalidCredentials.reject();
    }
    hashInfo.params = JSON.parse(hashInfo.params);
    switch (hashInfo.algorithm) {
        case 'pbkdf2':
            return new Promise((resolve, reject) => {
                crypto.pbkdf2(password, hashInfo.params.salt, hashInfo.params.iterations, hashInfo.params.keylen, hashInfo.params.digest, (err, key) => {
                    err ? reject(errors.Crypt.reject()) : resolve(key.toString('hex'));
                });
            });
    }
}

module.exports = {
    check: function(msg, $meta) {
        var get; // todo do some initial validation, to avoid unnecessary DB calls
        if (msg.username && msg.password) {
            get = this.bus.importMethod('user.identity.get')(msg, $meta)
            .then((userParams) => {
                // todo call bio.identity.check depending on userParams and msg
                return getHash(msg.password, userParams.length >= 1 && userParams[0].length === 1 && userParams[0][0]);
            });
        } else {
            get = Promise.resolve(null);
        }

        return get
            .then((hash) => {
                msg.password = hash;
                return this.bus.importMethod('user.identity.check')(msg, $meta);
            })
            .then((user) => {
                if (user.length === 1 && user[0] && user[0][0] && user[0][0].userId) { // in case user.identity.check did not return the permissions
                    return this.bus.importMethod('permission.get')(user[0][0].userId, $meta)
                        .then((permissions) => ([].concat(user, permissions)));
                }
                return user;
            });
    },
    closeSession: function(msg, $meta) {
        return this.bus.importMethod('user.identity.closeSession')(msg, $meta);
    },
    changePassword: function(msg, $meta) {
        return this.bus.importMethod('user.identity.changePassword')(msg, $meta);
    }
};
