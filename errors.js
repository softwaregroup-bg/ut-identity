var create = require('ut-error').define;

module.exports = [
    {
        name: 'identity.missingCredentials',
        defaultMessage: 'Missing credentials'
    },
    {
        name: 'identity.invalidCredentials',
        defaultMessage: 'Invalid credentials'
    },
    {
        name: 'identity.term.invalidNewPassword',
        defaultMessage: 'Invalid new password'
    },
    {
        name: 'identity.term.matchingPrevPassword',
        defaultMessage: 'Invalid new password. New password matches any of your previous passwords.'
    },
    {
        name: 'identity.expiredPassword',
        defaultMessage: 'Your password has expired! Please contact the system administrator.'
    },
    {
        name: 'identity.disabledUserInactivity',
        defaultMessage: 'Your account has been locked because of inactivity! Please contact the system administrator.'
    },
    {
        name: 'identity.disabledUser',
        defaultMessage: 'Your account has been locked! Please contact the system administrator.'
    },
    {
        name: 'identity.disabledCredentials',
        defaultMessage: 'Your credentials have been disabled! Please contact the system administrator.'
    },
    {
        name: 'identity.sessionExpired',
        defaultMessage: 'ut-identity identity.sessionExpired error'
    },
    {
        name: 'identity.invalidFingerprint',
        defaultMessage: 'ut-identity identity.invalidFingerprint error'
    },
    {
        name: 'identity.credentialsLocked',
        defaultMessage: 'ut-identity identity.credentialsLocked error'
    },
    {
        name: 'identity.wrongPassword',
        defaultMessage: 'ut-identity identity.wrongPassword error'
    },
    {
        name: 'identity.existingIdentifier',
        defaultMessage: 'ut-identity identity.existingIdentifier error'
    },
    {
        name: 'identity.crypt',
        defaultMessage: 'ut-identity identity.crypt error'
    },
    {
        name: 'identity.notFound',
        defaultMessage: 'Identity not found.'
    },
    {
        name: 'identity.multipleResults',
        defaultMessage: 'ut-identity identity.multipleResults error'
    },
    {
        name: 'identity.systemError',
        defaultMessage: 'ut-identity identity.systemError error'
    },
    {
        name: 'identity.throttleError',
        defaultMessage: 'After several attempts, the registration has been locked, please start again in 60 min.'
    },
].reduce(function(prev, next) {
    var spec = next.name.split('.');
    var Ctor = create(spec.pop(), spec.join('.'), next.defaultMessage);
    prev[next.name] = function(params) {
        return new Ctor({params: params});
    };
    return prev;
}, {});


// {
//     Identity: Identity,
// };

