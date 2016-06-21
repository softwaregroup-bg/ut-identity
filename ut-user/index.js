var errors = require('../errors');
var bus;
function getHash(password, hashInfo) {
    if (!hashInfo || !hashInfo.params) {
        return errors.MissingCredentials.reject();
    }
    hashInfo.params = typeof (hashInfo.params) === 'string' ? JSON.parse(hashInfo.params) : hashInfo.params;
    return bus.importMethod('user.genHash')(password, hashInfo.params);
}
var hashMethods = {
    otp: function(value, hashParams) {
        return getHash(value, hashParams);
    },
    password: function(value, hashParams) {
        return getHash(value, hashParams);
    },
    newPassword: function(value, hashParams) {
        return getHash(value, hashParams);
    },
    bio: function(value, hashParams) {
        var params = JSON.parse(hashParams);
        return bus.importMethod('bio.check')({
            id: params.id,
            departmentId: params.departmentId,
            data: value
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
        bus = b;
    },
    check: function(msg, $meta) {
        delete msg.type;
        var get;
        if (msg.sessionId) {
            get = Promise.resolve(msg);
        } else {
            $meta.method = 'user.identity.get'; // get hashes info
            get = bus.importMethod($meta.method)(msg, $meta)
                .then(function(result) {
                    if (!result.hashParams) {
                        throw new Error('no hash params');
                    }
                    var hashParams = result.hashParams.reduce(function(all, record) {
                        all[record.type] = record.params;
                        return all;
                    }, {});
                    return Promise.all(
                        Object.keys(hashMethods)
                            .filter(function(method) {
                                return hashParams[method] && msg[method];
                            })
                            .map(function(method) {
                                return hashMethods[method](msg[method], hashParams[method])
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
                $meta.method = 'user.identity.check';
                return bus.importMethod($meta.method)(r, $meta)
                    .then(function(user) {
                        if ((!user.loginPolicy || !user.loginPolicy.length) && !user['permission.get']) { // in case user.identity.check did not return the permissions
                            $meta.method = 'permission.get';
                            return bus.importMethod($meta.method)({actionId: msg.actionId},
                                {actorId: user['identity.check'].userId, actionId: 'identity.check'})
                                .then((permissions) => {
                                    user['permission.get'] = permissions && permissions[0];
                                    return user;
                                });
                        }
                        return user;
                    });
            });
    },
    closeSession: function(msg, $meta) {
        $meta.method = 'user.session.delete';
        return bus.importMethod($meta.method)({sessionId: $meta.auth.sessionId}, $meta);
    },
    changePassword: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        return bus.importMethod($meta.method)({
            userId: $meta.auth.actorId,
            type: 'password'
        }, $meta)
            .then((r) => {
                msg.hashParams = r.hashParams[0];
                $meta.method = 'user.changePassword';
                return bus.importMethod($meta.method)(msg, $meta);
            });
    }
};
