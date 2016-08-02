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
    registerPassword: getHash,
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
    registerRequest: function(msg, $meta) {
        var password = Math.floor(1000 + Math.random() * 9000) + '';
        var data = {};
        var result = {};
        var promises = [];
        // We have following flows in registration request:
        // 1. Registration flow (independent) - Create a password, hash it, try find/create/replace user.hash
        // 2. Template flow (independent) - Load a template to send SMS/email to user.
        // 3. Message flow (depends on 1 and 2) - If registration is successful and we have template, enqueue message to customer.
        promises.push(importMethod('user.getHash')(
            {
                value: password,
                type: 'registerPassword',
                identifier: msg.username
            }
        ).then(function(passwordHash) {
            msg.hash = passwordHash;
            return importMethod('user.identity.registerClient')(msg);
        }).then(function(identity) {
            data.identity = identity;
        }));
        // TODO: Replace with flow 2
        data.template = 'You have successfully registered. Your temporary password is:' + password;
        return Promise.all(promises).then(function() {
            var customerMessage = {
                // This data comes from flow 1
                port: data.identity.phone.mnoKey,
                recipient: data.identity.phone.phoneNumber,
                // TODO: this must be parsed template at flow 2
                content: data.template,
                priority: 1
            };
            return importMethod('alert.queue.push')(customerMessage, {
                auth: {
                    // This data comes from flow 1
                    actorId: data.identity.customer.actorId
                }
            });
        }).then(function() {
            return result;
        });
    },
    registerValidate: function(msg, $meta) {
        $meta.method = 'user.hash.return';
        return importMethod($meta.method)({
            identifier: msg.username,
            type: 'registerPassword'
        }, $meta).then(function(response) {
            if (!response.hashParams) {
                throw errors.NotFound();
            }
            return hashMethods.registerPassword(msg.registerPassword, response.hashParams);
        }).then(function(registerPassword) {
            msg.registerPassword = registerPassword;
            $meta.method = 'user.identity.registerPasswordValidate';
            return importMethod($meta.method)(msg, $meta);
        }).catch(handleError);
    },
    // TODO: Split this method in parts
    // TODO: 1a. If has forgottenPassword property, call identity.forgottenPasswordChange
    // TODO: 1b. If has registerPassword property, call identity.registerPasswordChange
    // TODO: 1c. Noop
    // TODO: 2. Call identity.hashPasswordFields
    // TODO: 3. Call identity.login
    // TODO: identity.registerPasswordChange should accept [registerPassword] and [newPassword] properties.
    // TODO: - It must call user.getHash (not getHash, because it calls user.genHash) to generate new hash object based on the "newPassword" field.
    // TODO: - It must insert/update with the data of the new hash object.
    // TODO: - It must return {"password": ..., "username": ...} where "password" is hash from the "newPassword" field.
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
            if (msg.hasOwnProperty('password') || msg.hasOwnProperty('registerPassword')) {
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
        if (msg.hasOwnProperty('registerPassword')) {
            if (msg.hasOwnProperty('password') || msg.hasOwnProperty('forgottenPassword')) {
                throw new errors.SystemError('invalid.request');
            }
            var hash = msg.newPassword == null ? Promise.resolve([]) : importMethod('user.getHash')({
                identifier: msg.username,
                value: msg.newPassword,
                type: 'password'
            });
            get = Promise.all([get, hash]).then(function() {
                var r = arguments[0][0];
                var hash = arguments[0][1];
                $meta.method = 'user.identity.registerPasswordChange';
                return importMethod($meta.method)({
                    username: r.username,
                    registerPassword: r.registerPassword,
                    hash: hash
                }).then(function() {
                    r.password = hash.value;
                    delete r.registerPassword;
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
