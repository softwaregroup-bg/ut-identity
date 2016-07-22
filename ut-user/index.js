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
    forgottenPassword: getHash,
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

var handleError = function(err) {
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
        if (msg.hasOwnProperty('forgottenPassword')) {
            if (msg.hasOwnProperty('password')) {
                throw new errors.SystemError('invalid.request');
            }
            get = get.then(function(r) {
                $meta.method = 'user.identity.forgottenPasswordChange';
                return importMethod($meta.method)(r).then(function() {
                    r.password = r.newPassword;
                    delete r.forgottenPassword;
                    delete r.newPassword;
                    return r;
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
            .catch(handleError);
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
    },
    forgottenPasswordRequest: function(msg, $meta) {
        // Use or to enum all possible channels here
        if (msg.channel !== 'sms') {
            throw new errors.NotFound();
        }
        $meta.method = 'user.identity.get';
        return importMethod($meta.method)({
            username: msg.username,
            type: 'password'
        }).then(function(hash) {
            if (!hash || !Array.isArray(hash.hashParams) || hash.hashParams.length < 1 || !hash.hashParams[0] || !hash.hashParams[0].actorId) {
                throw new errors.NotFound();
            }
            var actorId = hash.hashParams[0].actorId;
            $meta.method = 'user.sendOtp';
            return importMethod($meta.method)({
                channel: msg.channel,
                type: 'forgottenPassword',
                actorId: actorId
            }).then(function(result) {
                if (Array.isArray(result) && result.length >= 1 && Array.isArray(result[0]) && result[0].length >= 1 && result[0][0] && result[0][0].success) {
                    return {
                        sent: true
                    };
                }
                throw new errors.NotFound();
            });
        }).catch(handleError);
    },
    forgottenPasswordValidate: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        return importMethod($meta.method)({
            username: msg.username,
            type: 'forgottenPassword'
        }, $meta).then(function(response) {
            var hashParams;
            response.hashParams.some(function(h) {
                if (h.type === 'forgottenPassword') {
                    hashParams = h;
                    return true;
                }
                return false;
            });
            if (!hashParams) {
                throw errors.NotFound();
            }
            return hashMethods.forgottenPassword(msg.forgottenPassword, hashParams);
        }).then(function(forgottenPassword) {
            msg.forgottenPassword = forgottenPassword;
            $meta.method = 'user.identity.forgottenPasswordValidate';
            return importMethod($meta.method)(msg, $meta);
        }).catch(handleError);
    },
    forgottenPassword: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        var hashType = function(key, type, ErrorWhenNotFound) {
            return importMethod($meta.method)({
                username: msg.username,
                type: type
            }, $meta).then(function(response) {
                var hashParams;
                response.hashParams.some(function(h) {
                    if (h.type === type) {
                        hashParams = h;
                        return true;
                    }
                    return false;
                });
                if (!hashParams) {
                    if (ErrorWhenNotFound) {
                        throw new ErrorWhenNotFound();
                    } else {
                        return null;
                    }
                }
                return msg[key] ? hashMethods[type](msg[key], hashParams) : null;
            });
        };
        return Promise.all([
            hashType('forgottenPassword', 'forgottenPassword', errors.NotFound),
            hashType('newPassword', 'password', null)
        ]).then(function(p) {
            msg.forgottenPassword = p[0];
            msg.newPassword = p[1];
            $meta.method = 'user.identity.forgottenPasswordChange';
            return importMethod($meta.method)(msg, $meta);
        }).catch(handleError);
    }
};
