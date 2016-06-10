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
        if (msg.fingerprints) {
            // bio logic
            $meta.method = 'user.identity.get';
            get = this.bus.importMethod($meta.method)(msg, $meta)
            .then((r) => {
                var params = r.hashParams[0].params && JSON.parse(r.hashParams[0].params);
                if (!params) {
                    $meta.mtid = 'error';
                    return {
                        code: 4444,
                        message: 'User is not bio enrolled'
                    };
                }
                $meta.method = 'bio.check';
                return this.bus.importMethod($meta.method)({
                    id: params.id,
                    departmentId: params.departmentId,
                    data: msg.fingerprints
                }, $meta);
            })
            .then(function(r) {
                return {
                    username: msg.username,
                    password: '***', // workaround for now - bio has a priority but a session is not created if password IS NULL
                    bio: '123' // change Api later to pass fingerprint index (identifier)
                };
            });
        } else if (msg.sessionId) {
            get = Promise.resolve(msg);
        } else {
            $meta.method = 'user.identity.get';
            get = this.bus.importMethod($meta.method)(msg, $meta)
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
                $meta.method = 'user.identity.check';
                return this.bus.importMethod($meta.method)(r, $meta)
                .then((user) => {
                    if (user.loginPolicy && user.loginPolicy.length > 0) {
                        return {loginPolicy: user.loginPolicy};
                    }
                    if (!user['permission.get']) { // in case user.identity.check did not return the permissions
                        $meta.method = 'permission.get';
                        return this.bus.importMethod($meta.method)({actionId: msg.actionId},
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
        $meta.method = 'user.session.delete';
        return this.bus.importMethod($meta.method)({sessionId: $meta.auth.sessionId}, $meta);
    },
    changePassword: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        return this.bus.importMethod($meta.method)({userId: $meta.auth.actorId}, $meta)
        .then((r) => {
            msg.hashParams = r.hashParams[0];
            $meta.method = 'user.changePassword';
            return this.bus.importMethod($meta.method)(msg, $meta);
        });
    }
};
