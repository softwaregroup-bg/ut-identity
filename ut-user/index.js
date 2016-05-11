var errors = require('../errors');
var crypto = require('crypto');

function getHash(password, hashInfo) {
    if (!hashInfo || !hashInfo.params) {
        return errors.InvalidCredentials.reject();
    }
    hashInfo.params = typeof (hashInfo.params) === 'string' ? JSON.parse(hashInfo.params) : hashInfo.params;
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
                return getHash(msg.password, userParams.length >= 1 && userParams[0].length === 1 && userParams[0][0])
                .then((oldHash) => {
                    if (msg.newPassword) { // change password case
                        return getHash(msg.newPassword, userParams.length >= 1 && userParams[0].length === 1 && userParams[0][0])
                        .then((newHash) => {
                            return {oldHash: oldHash, newHash: newHash};
                        });
                    } else {
                        return {oldHash: oldHash};
                    }
                });
            })
            .then((hashes) => {
                msg.password = hashes.oldHash;
                if (msg.newPassword) {
                    msg.newPassword = hashes.newHash;
                }
                return msg;
            });
        } else if (msg.username && msg.fingerprints && msg.fingerprints.length > 0) {
            msg.fingerprint = 1;
            get = this.bus.importMethod('user.identity.get')(msg, $meta)
            .then((r) => {
                return this.bus.importMethod('bio.check')(msg, $meta);
            });
        } else {
            get = Promise.resolve(msg);
        }

        return get
            .then((msg) => {
                return this.bus.importMethod('user.identity.check')(msg, $meta);
            })
            .then((user) => {
                if (!user['permission.get']) { // in case user.identity.check did not return the permissions
                    return this.bus.importMethod('permission.get')({}, {actorId: user['identity.check'][0].userId, actionId: 'identity.check'})
                        .then((permissions) => {
                            user['permission.get'] = permissions;
                            return user;
                        });
                }
                return user;
            });
    },
    closeSession: function(msg, $meta) {
        return this.bus.importMethod('user.session.delete')({sessionId: $meta.auth.sessionId}, $meta);
    },
    changePassword: function(msg, $meta) {
        return this.bus.importMethod('user.identity.changePassword')(msg, $meta);
    }
};
