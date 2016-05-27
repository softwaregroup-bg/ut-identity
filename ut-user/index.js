var errors = require('../errors');
var crypto = require('crypto');

function getHash(password, hashInfo) {
    if (!hashInfo || !hashInfo.params) {
        return errors.MissingCredentials.reject();
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
        var get;
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
            get = this.bus.importMethod('user.identity.get')(msg, $meta)
            .then((r) => {
                return this.bus.importMethod('bio.check')({data: msg.fingerprints, bioId: r[0][0].bioid}, $meta);
            })
            .then((r) => ({bioid: r.bioId, username: msg.username, actionId: msg.actionId}));
        } else if (msg.sessionId) {
            get = Promise.resolve(msg);
        } else if (msg.username) {
            msg.identifier = msg.username;
            return this.bus.importMethod('user.policy.get')(msg, $meta);
        } else {
            get = Promise.resolve({});
        }

        return get
            .then((r) => {
                if (!r.actionId) {
                    return errors.MissingCredentials.reject();
                }
                return r;
            })
            .then((r) => (this.bus.importMethod('user.identity.check')(r, $meta)))
            .then((user) => {
                if (!user['permission.get']) { // in case user.identity.check did not return the permissions
                    return this.bus.importMethod('permission.get')({actionId: msg.actionId},
                        {actorId: user['identity.check'].userId, actionId: 'identity.check'})
                        .then((permissions) => {
                            user['permission.get'] = permissions && permissions[0];
                            return user;
                        });
                }
                return user;
            })
            .catch((err) => {
                throw new errors.InvalidCredentials(err);
            });
    },
    closeSession: function(msg, $meta) {
        return this.bus.importMethod('user.session.delete')({sessionId: $meta.auth.sessionId}, $meta);
    },
    changePassword: function(msg, $meta) {
        return this.bus.importMethod('user.identity.get')({userId: $meta.auth.actorId}, $meta)
        .then((r) => {
            msg.hashParams = r[0][0];
            return this.bus.importMethod('user.changePassword')(msg, $meta);
        });
    }
};
