var assign = require('lodash.assign');
var errors = require('../errors');
var importMethod;
var checkMethod;
var debug;
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
            err.type === 'policy.term.checkOTP' ||
            err.type === 'user.identity.registerPasswordValidate.expiredPassword' ||
            err.type === 'user.identity.registerPasswordChange.expiredPassword' ||
            err.type === 'user.identity.registerPasswordValidate.invalidCredentials' ||
            err.type === 'user.identity.registerPasswordChange.invalidCredentials' ||
            err.type === 'identity.invalidFingerprint' ||
            err.type.startsWith('policy.param.')
        ) {
            throw err;
        } else if (
            err.type === 'user.identity.forgottenPasswordValidate.invalidCredentials' ||
            err.type === 'user.identity.forgottenPasswordValidate.expiredPassword' ||
            err.type === 'user.identity.forgottenPasswordValidate.notFound' ||
            err.type === 'user.identity.check.userPassword.wrongPassword' ||
            err.type === 'user.identity.checkPolicy.notFound' ||
            err.type === 'user.identity.check.userPassword.notFound' ||
            err.type === 'user.identity.checkPolicy.disabledCredentials' ||
            err.type === 'user.identity.check.disabledUser' ||
            err.type === 'user.identity.check.disabledUserInactivity' ||
            err.type === 'user.identity.checkPolicy.disabledUserInactivity' ||
            err.type === 'identity.credentialsLocked' ||
            err.type === 'identity.notFound' ||
            err.type === 'identity.multipleResults' ||
            err.type.startsWith('policy.term.')
        ) {
            throw new errors.InvalidCredentials(err);
        }
    }
    if (err.type === 'core.throttle' || err.message === 'core.throttle') {
        throw new errors.ThrottleError(err);
    }
    throw new errors.SystemError(err);
};

module.exports = {
    init: function(b) {
        importMethod = b.importMethod.bind(b);
        checkMethod = b.config['identity.check'];
        debug = b.config.debug;
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
            if (!identity.phone || !identity.phone.phoneNumber) {
                throw errors.NotFound();
            }
            data.identity = identity;
            return;
        }));
        return Promise.all(promises).then(function() {
            var customerMessage = {
                // This data comes from flow 1
                port: data.identity.phone.mnoKey,
                recipient: data.identity.phone.phoneNumber,
                template: 'customer.self.registration.otp',
                data: {
                    firstName: data.identity.person.firstName,
                    hash: password
                },
                languageCode: msg.language,
                priority: 1
            };
            return importMethod('alert.message.send')(customerMessage, assign({}, $meta, {
                auth: {
                    actorId: data.identity.customer.actorId
                },
                method: 'alert.message.send'
            }));
        }).then(function() {
            if (debug) {
                result.otp = password;
            }
            return result;
        }).catch(handleError);
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
    check: function(msg, $meta) {
        delete msg.type;
        var creatingSession = false;
        var get;
        if (msg.sessionId) {
            get = Promise.resolve(msg);
        } else {
            creatingSession = true;
            $meta.method = 'user.identity.get'; // get hashes info
            get = importMethod($meta.method)(msg, $meta)
                .then(function(result) {
                    if (!result.hashParams) {
                        throw new Error('no hash params');
                    }
                    var hashData = result.hashParams.reduce(function(all, record) {
                        all[record.type] = record;
                        msg.actorId = record.actorId;
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
                                        return;
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
            }).then(function(response) {
                if (creatingSession && response.roles.some((role) => role.name === 'BaobabClientApplication')) {
                    return importMethod('customer.activityReport.add')({
                        activity: {
                            installationId: msg.username,
                            action: 'identity.login',
                            actionStatus: 'success',
                            operationDate: (new Date()).toISOString(),
                            channel: 'online'
                        }
                    }, {
                        auth: {
                            actorId: response['identity.check'].actorId
                        }
                    }).then(() => response);
                }
                return response;
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
            })
            .catch(handleError);
    },
    forgottenPasswordRequest: function(msg, $meta) {
        // Use or to enum all possible channels here
        if (msg.channel !== 'sms' && msg.channel !== 'email') {
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
                template: 'user.forgottenPassword.otp',
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
                var rr = msg[key] ? hashMethods[type](msg[key], hashParams) : null;
                return rr;
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
