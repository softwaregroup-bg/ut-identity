var errors = require('../errors');
var importMethod;
var checkMethod;
function getHash(password, hashData) {
    if (!hashData || !hashData.params) {
        return errors.MissingCredentials.reject();
    }
    hashData.params = typeof (hashData.params) === 'string' ? JSON.parse(hashData.params) : hashData.params;
    return importMethod('user.genHash')(password, hashData.params);
}

var hashMethods = {
    otp: getHash,
    password: getHash,
    newPassword: getHash,
    bio: function(value, hashData) {
        var params = JSON.parse(hashData.params);
        return importMethod('bio.check')({
            id: params.id,
            departmentId: params.departmentId,
            data: {
                UK: [value]
            }
        })
        .then(function(r) {
            return 1;
        })
        .catch(function(r) {
            return 0;
        });
    }
};

module.exports = {
    init: function(b) {
        importMethod = b.importMethod.bind(b);
        checkMethod = b.config['identity.check'];
    },
    add: function(msg, $meta) {
        var password = Math.floor(1000 + Math.random() * 9000) + '';
        var result = {};
        return importMethod('user.getHash')({value: password, type: 'password', identifier: msg.username})
            .then((hash) => {
                msg.hash = hash;
                return importMethod('user.identity.add')(msg);
            })
            .then((identity) => {
                var msg = {
                    priority: 1
                };
                if (msg.email) {
                    msg.port = 'email';
                    msg.recipient = msg.email;
                    msg.content = {
                        subject: 'self registration',
                        text: 'You have successfully registered. Your temporary password is:' + password
                    };
                } else {
                    var phoneNumber = identity.actor.phoneNumber;
                    if (phoneNumber.charAt(0) === '+') {
                        phoneNumber = phoneNumber.substr(1);
                    }
                    msg.port = identity.actor.mnoKey;
                    msg.recipient = phoneNumber;
                    msg.content = 'You have successfully registered. Your temporary password is: ' + password;
                }
                return importMethod('alert.queue.push')(msg, {auth: {actorId: identity.actor.actorId}});
            }).then(function() {
                return result;
            });
    },
    check: function(msg, $meta) {
        delete msg.type;
        var get;
        if (msg.sessionId) {
            get = Promise.resolve(msg);
        // } else if (msg.sendOtp) { // check password maybe
        //     get = sendOtp(msg.username, msg.sendOtp);
        } else {
            $meta.method = 'user.identity.get'; // get hashes info
            get = importMethod($meta.method)(msg, $meta)
                .then(function(result) {
                    if (!result.hashParams) {
                        throw new Error('no hash params');
                    }
                    var hashData = result.hashParams.reduce(function(all, record) {
                        all[record.type] = record;
                        return all;
                    }, {});
                    if (msg.newPassword && hashData.password) {
                        hashData.newPassword = hashData.password;
                    }
                    return Promise.all(
                        Object.keys(hashMethods)
                            .filter(function(method) {
                                return hashData[method] && msg[method];
                            })
                            .map(function(method) {
                                return hashMethods[method](msg[method], hashData[method])
                                    .then(function(value) {
                                        msg[method] = value;
                                    });
                            })
                    )
                    .then(function() {
                        return msg;
                    });
                });
        }
        return get
            .then(function(r) {
                $meta.method = checkMethod || 'user.identity.checkPolicy';
                return importMethod($meta.method)(r, $meta)
                    .then(function(user) {
                        if ((!user.loginPolicy || !user.loginPolicy.length) && !user['permission.get']) { // in case user.identity.check did not return the permissions
                            $meta.method = 'permission.get';
                            return importMethod($meta.method)({actionId: msg.actionId},
                                {actorId: user['identity.check'].userId, actionId: 'identity.check'})
                                .then((permissions) => {
                                    user['permission.get'] = permissions && permissions[0];
                                    return user;
                                });
                        }
                        return user;
                    });
            })
            .catch(function(err) {
                if (typeof err.type === 'string') {
                    if (
                        err.type === 'policy.term.checkBio' ||
                        err.type === 'identity.expiredPassword' ||
                        err.type === 'identity.invalidCredentials' ||
                        err.type === 'identity.invalidFingerprint' ||
                        err.type.startsWith('policy.param.')
                    ) {
                        throw err;
                    } else if (
                        err.type === 'identity.wrongPassword' ||
                        err.type === 'identity.notFound' ||
                        err.type === 'identity.disabledCredentials' ||
                        err.type === 'identity.disabledUser' ||
                        err.type === 'identity.disabledUserInactivity' ||
                        err.type === 'identity.credentialsLocked' ||
                        err.type.startsWith('policy.term.')
                    ) {
                        throw new errors.InvalidCredentials(err);
                    }
                }
                throw new errors.SystemError(err);
            });
    },
    closeSession: function(msg, $meta) {
        $meta.method = 'user.session.delete';
        return importMethod($meta.method)({sessionId: $meta.auth.sessionId}, $meta);
    },
    changePassword: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        return importMethod($meta.method)({
            userId: $meta.auth.actorId,
            type: 'password'
        }, $meta)
            .then((r) => {
                msg.hashParams = r.hashParams[0];
                $meta.method = 'user.changePassword';
                return importMethod($meta.method)(msg, $meta);
            });
    }
};
