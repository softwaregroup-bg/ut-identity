var create = require('ut-error').define;

var Identity = create('Identity');
module.exports = {
    MissingCredentials: create('MissingCredentials', Identity),
    InvalidCredentials: create('InvalidCredentials', Identity),
    ExpiredPassword: create('ExpiredPassword', Identity),
    SessionExpired: create('SessionExpired', Identity),
    InvalidFingerprint: create('InvalidFingerprint', Identity),
    Identity: Identity
};

Object.getOwnPropertyNames(module.exports).forEach(function(key) {
    var Method = module.exports[key];
    Method.reject = function() {
        return Promise.reject(new Method(arguments)); // todo improve arguments passing
    };
});
