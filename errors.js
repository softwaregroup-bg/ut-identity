var create = require('ut-error').define;

var Identity = create('identity');
module.exports = {
    MissingCredentials: create('missingCredentials', Identity, 'Missing credentials'),
    InvalidCredentials: create('invalidCredentials', Identity, 'Invalid credentials'),
    ExpiredPassword: create('expiredPassword', Identity, 'Your password has expired! Please contact the system administrator.'),
    DisabledUserInactivity: create('disabledUserInactivity', Identity, 'Your account has been locked because of inactivity! Please contact the system administrator.'),
    DisabledUser: create('disabledUser', Identity, 'Your account has been locked! Please contact the system administrator.'),
    DisabledCredentials: create('disabledCredentials', Identity, 'Your credentials have been disabled! Please contact the system administrator.'),
    SessionExpired: create('sessionExpired', Identity),
    InvalidFingerprint: create('invalidFingerprint', Identity),
    CredentialsLocked: create('credentialsLocked', Identity),
    WrongPassword: create('wrongPassword', Identity),
    ExistingIdentifier: create('existingIdentifier', Identity),
    Identity: Identity,
    Crypt: create('crypt', Identity),
    NotFound: create('notFound', Identity, 'Identity not found.'),
    MultipleResults: create('multipleResults', Identity),
    SystemError: create('systemError', Identity),
    ThrottleError: create('throttleError', Identity, '')
};

Object.getOwnPropertyNames(module.exports).forEach(function(key) {
    var Method = module.exports[key];
    Method.reject = function() {
        return Promise.reject(new Method(arguments)); // todo improve arguments passing
    };
});
