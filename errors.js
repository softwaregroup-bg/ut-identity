var create = require('ut-error').define;

var Identity = create('Identity');
module.exports = {
    MissingCredentials: create('MissingCredentials', Identity, 'Missing credentials'),
    InvalidCredentials: create('InvalidCredentials', Identity, 'Invalid credentials'),
    ExpiredPassword: create('ExpiredPassword', Identity),
    SessionExpired: create('SessionExpired', Identity),
    InvalidFingerprint: create('InvalidFingerprint', Identity),
    Identity: Identity,
    Crypt: create('crypt', Identity),
    MultipleResults: create('multipleResults', Identity)
};

Object.getOwnPropertyNames(module.exports).forEach(function(key) {
    var Method = module.exports[key];
    Method.reject = function() {
        return Promise.reject(new Method(arguments)); // todo improve arguments passing
    };
});
