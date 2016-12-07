var assign = require('lodash.assign');
var errors = require('../errors');
var helpers = require('./helpers');
var utUserHelpers = require('ut-user/helpers');
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
    bio: function(values, hashData) {
        // values - array like: [{finger: "L1", templates: ["RRMNDKSF...]}, {finger: "L2", templates: ["RRMNDKSF...]}].
        // where finger could be one of 'L1', 'L2', 'L3', 'L4', 'L5', 'R1', 'R2', 'R3', 'R4', 'R5'
        // Joi validations validates that
        var mappedBioData = {};
        var successDataResponse = [];
        values.forEach(function(val) {
            mappedBioData[val.finger] = val.templates;
            successDataResponse.push(val.finger);
        });

        // Validate output object
        if (Object.keys(mappedBioData).length === 0) {
            return new Promise(function(resolve, reject) {
                resolve(['']);
            });
        }

        /*
            Bio server example request:
            id: params.id,
            departmentId: params.departmentId,
            data: {
                UK: [value]
            }
        */

        // On this stage BIO server can check one finger at time.
        var bioCheckPromises = [];
        var params = JSON.parse(hashData.params);
        for (var finger in mappedBioData) {
            if (mappedBioData.hasOwnProperty(finger)) {
                var currentData = {};
                currentData[finger] = mappedBioData[finger];
                bioCheckPromises.push(importMethod('bio.check')({
                    id: params.id,
                    departmentId: params.departmentId,
                    data: currentData
                }));
            }
        }

        return Promise.all(bioCheckPromises)
            .then(function(r) {
                return successDataResponse;
            })
            .catch(function(r) {
                return [''];
            });
    }
};

/*
    passwordCredentaislGetStoreProcedureParams - could have hashed password, if not we are hasheing in the method but we need params
*/
/**
 * Validates password against user Access policy. E.g. Passowrd lenght and required symbols (lower case, special symbol, etc.)
 * @param {newPasswordRaw} plain new password
 * @param {passwordCredentaislGetStoreProcedureParams} params that 'policy.passwordCredentials.get' Store procedure requires
 *  username: string
 *  type: one of forgottenPassword|registerPassword|password
 *  password: string. Could be plain or hashed. However, the store procedure requires hashed password therefore additional properties
 *     could be passed to this object to make this method to hash the password: requiresPassHash and hashParams
 *  requiresPassHash: boolen. If this property is true the method will require to pass hashParams as well
 *  hashParams: object having params property. Used to hash the password with the passed params
 * @param {$meta} object
 * @param {actorId} number|string. Required only if $meta object has no 'auth.actorId' propepry.
 *  Store procedure 'core.itemTranslation.fetch' requires actorId. This SP will be executed if the new password does not match the access policy
 *  and appropriate message need to be displayed to the user
 *
 * Return true or throws error
 */
function validateNewPasswordAgainstAccessPolicy(newPasswordRaw, passwordCredentaislGetStoreProcedureParams, $meta, actorId) {
    // There are cases iwhere we passes the current hashed password => no need to hash it
    var hashPassword = new Promise(function(resolve, reject) {
        if (passwordCredentaislGetStoreProcedureParams.requiresPassHash) {
            var hashParams = passwordCredentaislGetStoreProcedureParams.hashParams;
            var password = passwordCredentaislGetStoreProcedureParams.password;
            if (hashParams && password) {
                utUserHelpers.genHash(password, JSON.parse(hashParams.params))
                    .then(function(hashedPassword) {
                        resolve(hashedPassword);
                    });
            } else {
                throw errors['identity.hashParams']();
            }
        } else {
            resolve(passwordCredentaislGetStoreProcedureParams.password);
        }
    });

    return hashPassword
    .then(function(hashedPassword) {
        var policyPasswordCredentalsGetParams = {
            username: passwordCredentaislGetStoreProcedureParams.username,
            type: passwordCredentaislGetStoreProcedureParams.type,
            password: hashedPassword
        };
        return importMethod('policy.passwordCredentials.get')(policyPasswordCredentalsGetParams)
        .then(function(policyResult) {
            // Validate password policy
            var passwordCredentials = policyResult['passwordCredentials'][0];
            var isPasswordValid = utUserHelpers.isParamValid(newPasswordRaw, passwordCredentials);
            if (isPasswordValid) {
                // Validate previous password
                var previousPasswords = policyResult['previousPasswords'] || [];

                var genHashPromises = [];
                var cachedHashPromises = {};
                var cachedHashPromisesPrevPassMap = {}; // stores index from genHash to which prevPassword index is, in order to avoid generating the same hash multiple times

                var prevPassMapIndex = -1;
                for (var i = 0; i < previousPasswords.length; i += 1) {
                    var currentPrevPasswordObj = previousPasswords[i];
                    var currentPassWillBeCached = cachedHashPromises[currentPrevPasswordObj.params];
                    if (!currentPassWillBeCached) {
                        genHashPromises.push(utUserHelpers.genHash(newPasswordRaw, JSON.parse(currentPrevPasswordObj.params)));
                        cachedHashPromises[currentPrevPasswordObj.params] = true;
                        prevPassMapIndex += 1;
                    }

                    cachedHashPromisesPrevPassMap[i] = prevPassMapIndex;
                }

                return Promise.all(genHashPromises).then((res) => {
                    var newPassMatchPrev = false;

                    for (var i = 0; i < previousPasswords.length && !newPassMatchPrev; i += 1) {
                        var currentPrevPassword = previousPasswords[i];
                        var currentHashIndex = cachedHashPromisesPrevPassMap[i];
                        var currentNewHashedPassword = res[currentHashIndex];
                        if (currentPrevPassword.value === currentNewHashedPassword) {
                            newPassMatchPrev = true;
                        }
                    }

                    if (newPassMatchPrev) {
                        throw errors['identity.term.matchingPrevPassword']();
                    } else {
                        return true;
                    }
                });
            } else {
                if (!$meta['auth.actorId']) {
                    if (!actorId) {
                        throw errors['identity.actorId']();
                    }
                    $meta['auth.actorId'] = actorId;
                }
                return importMethod('core.itemTranslation.fetch')({
                    itemTypeName: 'regexInfo',
                    languageId: 1 // the languageId should be passed by the UI, it should NOT be the user default language becase the UI can be in english and the default user language might be france
                }, $meta).then(function(translationResult) {
                    var printMessage = helpers.buildPolicyErrorMessage(translationResult.itemTranslationFetch, passwordCredentials.regexInfo, passwordCredentials.charMin, passwordCredentials.charMax);
                    var invalidNewPasswordError = errors['identity.term.invalidNewPassword'](printMessage);
                    invalidNewPasswordError.message = printMessage;
                    throw invalidNewPasswordError;
                });
            }
        });
    });
}

var handleError = function(err) {
    if (typeof err.type === 'string') {
        if (
            err.type === 'policy.term.checkBio' ||
            err.type === 'policy.term.checkOTP' ||
            err.type === 'identity.term.invalidNewPassword' ||
            err.type === 'identity.term.matchingPrevPassword' ||
            err.type === 'user.identity.registerPasswordValidate.expiredPassword' ||
            err.type === 'user.identity.registerPasswordChange.expiredPassword' ||
            err.type === 'user.identity.registerPasswordValidate.invalidCredentials' ||
            err.type === 'user.identity.registerPasswordChange.invalidCredentials' ||
            err.type === 'identity.invalidFingerprint' ||
            err.type === 'user.identity.checkPolicy.invalidLoginTime' ||
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
            throw errors['identity.invalidCredentials'](err);
        } else if (err.type === 'PortSQL' && (err.message.startsWith('policy.param.bio.fingerprints')) || err.message.startsWith('policy.term.checkBio')) {
            err.type = err.message;
            throw err;
        }
    }
    if (err.type === 'core.throttle' || err.message === 'core.throttle') {
        throw errors['identity.throttleError'](err);
    }
    throw errors['identity.systemError'](err);
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
                throw errors['identity.notFound']();
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
                throw errors['identity.notFound']();
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
            if (msg.newPassword) {
                msg.newPasswordRaw = msg.newPassword;
            }
            get = importMethod($meta.method)(msg, $meta)
                .then(function(result) {
                    if (!result.hashParams) {
                        throw errors['identity.hashParams']();
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
        if (msg.hasOwnProperty('newPassword') && !msg.hasOwnProperty('registerPassword')) {
            if (msg.hasOwnProperty('forgottenPassword') && msg.hasOwnProperty('registerPassword')) {
                throw errors['identity.systemError']('invalid.request');
            }

            // Validate new password access policy
            get = Promise.all([get]).then(function() {
                var rawNewPassword = arguments[0][0]['newPasswordRaw'];
                var okReturn = arguments[0][0];

                // The SP receives type param which determines which action should be taken
                var type;
                var password;

                if (msg.hasOwnProperty('forgottenPassword')) {
                    type = 'forgottenPassword';
                    password = msg.forgottenPassword;
                } else if (msg.hasOwnProperty('registerPassword')) {
                    type = 'registerPassword';
                    password = msg.registerPassword;
                } else {
                    type = 'password';
                    password = msg.password;
                }

                var passwordCredentaislGetStoreProcedureParams = {
                    username: msg.username,
                    type: type,
                    password: password
                };

                return validateNewPasswordAgainstAccessPolicy(rawNewPassword, passwordCredentaislGetStoreProcedureParams, $meta, msg.actorId)
                    .then(() => {
                        return okReturn;
                    });
            });
        }
        if (msg.hasOwnProperty('forgottenPassword')) {
            if (msg.hasOwnProperty('password') || msg.hasOwnProperty('registerPassword')) {
                throw errors['identity.systemError']('invalid.request');
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
                throw errors['identity.systemError']('invalid.request');
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
                var passwordCredentaislGetStoreProcedureParams = {
                    username: msg.username,
                    type: 'password',
                    password: msg.password,
                    requiresPassHash: true,
                    hashParams: r.hashParams[0]
                };

                msg.hashParams = r.hashParams[0];
                return validateNewPasswordAgainstAccessPolicy(msg.newPassword, passwordCredentaislGetStoreProcedureParams, $meta);
            })
            .then(() => {
                $meta.method = 'user.changePassword';
                return importMethod($meta.method)(msg, $meta);
            })
            .catch(handleError);
    },
    forgottenPasswordRequest: function(msg, $meta) {
        // Use or to enum all possible channels here
        if (msg.channel !== 'sms' && msg.channel !== 'email') {
            throw errors['identity.notFound']();
        }
        $meta.method = 'user.identity.get';
        return importMethod($meta.method)({
            username: msg.username,
            type: 'password'
        }).then(function(hash) {
            if (!hash || !Array.isArray(hash.hashParams) || hash.hashParams.length < 1 || !hash.hashParams[0] || !hash.hashParams[0].actorId) {
                throw errors['identity.notFound']();
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
                throw errors['identity.notFound']();
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
                throw errors['identity.notFound']();
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
            hashType('forgottenPassword', 'forgottenPassword', errors['identity.notFound']()),
            hashType('newPassword', 'password', null)
        ]).then(function(p) {
            msg.forgottenPassword = p[0];
            msg.newPassword = p[1];
            $meta.method = 'user.identity.forgottenPasswordChange';
            return importMethod($meta.method)(msg, $meta);
        }).catch(handleError);
    }
};
