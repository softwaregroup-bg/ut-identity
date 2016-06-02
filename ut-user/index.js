var errors = require('../errors');
var genHash;
function getHash(password, hashInfo) {
    if (!hashInfo || !hashInfo.params) {
        return errors.MissingCredentials.reject();
    }
    hashInfo.params = typeof (hashInfo.params) === 'string' ? JSON.parse(hashInfo.params) : hashInfo.params;
    return genHash(password, hashInfo.params);
}

module.exports = {
    check: function(msg, $meta) {
        var get;
        genHash = this.bus.importMethod('user.genHash');
        if (msg.fingerprints && msg.fingerprints.length > 0) {
            // bio logic
            get = this.bus.importMethod('user.identity.get')(msg, $meta)
            .then((r) => {
                return this.bus.importMethod('bio.check')({data: msg.fingerprints, bioId: r[0][0].bioid}, $meta);
            })
            .then((r) => ({bioid: r.bioId, username: msg.username, actionId: msg.actionId}));
        } else if (msg.sessionId) {
            get = Promise.resolve(msg);
        } else {
            get = this.bus.importMethod('user.identity.get')(msg, $meta)
            .then((userParams) => {
                var hashQueue = userParams.hashParams
                .filter((hp) => (msg[hp.type]))
                .map((hp) => {
                    var hashValue = msg[hp.type]; // what to hash, otp or password
                    return getHash(hashValue, hp)
                    .then((oldHash) => {
                        msg[hp.type] = oldHash;
                        if (msg.newPassword && hp.type === 'password') { // change password case
                            return getHash(msg.newPassword, hp)
                            .then((newHash) => {
                                msg.newPassword = newHash;
                                return msg;
                            });
                        }
                        return msg;
                    });
                });

                return Promise.all(hashQueue)
                .then(() => (msg));
            });
        }

        return get
            .then((r) => {
                return this.bus.importMethod('user.identity.check')(r, $meta)
                .then((user) => {
                    if (user.loginPolicy && user.loginPolicy.length > 0) {
                        return {loginPolicy: user.loginPolicy};
                    }
                    if (!user['permission.get']) { // in case user.identity.check did not return the permissions
                        return this.bus.importMethod('permission.get')({actionId: msg.actionId},
                            {actorId: user['identity.check'].userId, actionId: 'identity.check'})
                            .then((permissions) => {
                                user['permission.get'] = permissions && permissions[0];
                                return user;
                            });
                    }
                    return user;
                });
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
            msg.hashParams = r.hashParams[0];
            return this.bus.importMethod('user.changePassword')(msg, $meta);
        });
    }
};
