var errors = require('../errors');
var bus;
function getHash(password, hashData) {
    if (!hashData || !hashData.params) {
        return errors.MissingCredentials.reject();
    }
    hashData.params = typeof (hashData.params) === 'string' ? JSON.parse(hashData.params) : hashData.params;
    return bus.importMethod('user.genHash')(password, hashData.params);
}
var hashMethods = {
    otp: function(value, hashData) {
        return getHash(value, hashData);
    },
    password: function(value, hashData) {
        return getHash(value, hashData);
    },
    newPassword: function(value, hashData) {
        return getHash(value, hashData);
    },
    bio: function(value, hashData) {
        var params = JSON.parse(hashData.params);
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
                    var hashData = result.hashParams.reduce(function(all, record) {
                        all[record.type] = record;
                        return all;
                    }, {});
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
