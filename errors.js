var create = require('ut-error').define;

module.exports = [
    {
        name: 'identity',
        defaultMessage: 'Identity',
        level: 'error'
    },
    {
        name: 'identity.missingCredentials',
        defaultMessage: 'Missing credentials',
        level: 'error'
    },
    {
        name: 'identity.invalidCredentials',
        defaultMessage: 'Invalid credentials',
        level: 'error'
    },
    {
        name: 'identity.hashParams',
        defaultMessage: 'No hash params',
        level: 'error'
    },
    {
        name: 'identity.actorId',
        defaultMessage: 'No actor id param',
        level: 'error'
    },
    {
        name: 'identity.term',
        defaultMessage: 'ut-identity identity.term error',
        level: 'error'
    },
    {
        name: 'identity.term.invalidNewPassword',
        defaultMessage: 'Invalid new password',
        level: 'error'
    },
    {
        name: 'identity.term.matchingPrevPassword',
        defaultMessage: 'Invalid new password. New password matches any of your previous passwords.',
        level: 'error'
    },
    {
        name: 'identity.expiredPassword',
        defaultMessage: 'Your password has expired! Please contact the system administrator.',
        level: 'error'
    },
    {
        name: 'identity.disabledUserInactivity',
        defaultMessage: 'Your account has been locked because of inactivity! Please contact the system administrator.',
        level: 'error'
    },
    {
        name: 'identity.disabledUser',
        defaultMessage: 'Your account has been locked! Please contact the system administrator.',
        level: 'error'
    },
    {
        name: 'identity.disabledCredentials',
        defaultMessage: 'Your credentials have been disabled! Please contact the system administrator.',
        level: 'error'
    },
    {
        name: 'identity.sessionExpired',
        defaultMessage: 'ut-identity identity.sessionExpired error',
        level: 'error'
    },
    {
        name: 'identity.invalidFingerprint',
        defaultMessage: 'ut-identity identity.invalidFingerprint error',
        level: 'error'
    },
    {
        name: 'identity.credentialsLocked',
        defaultMessage: 'ut-identity identity.credentialsLocked error',
        level: 'error'
    },
    {
        name: 'identity.wrongPassword',
        defaultMessage: 'ut-identity identity.wrongPassword error',
        level: 'error'
    },
    {
        name: 'identity.existingIdentifier',
        defaultMessage: 'ut-identity identity.existingIdentifier error',
        level: 'error'
    },
    {
        name: 'identity.restrictedRange',
        defaultMessage: 'IP is in the restricted range',
        level: 'error'
    },
    {
        name: 'identity.wrongIP',
        defaultMessage: 'Wrong ip address',
        level: 'error'
    },
    {
        name: 'identity.crypt',
        defaultMessage: 'ut-identity identity.crypt error',
        level: 'error'
    },
    {
        name: 'identity.notFound',
        defaultMessage: 'Identity not found.',
        level: 'error'
    },
    {
        name: 'identity.multipleResults',
        defaultMessage: 'ut-identity identity.multipleResults error',
        level: 'error'
    },
    {
        name: 'identity.systemError',
        defaultMessage: 'ut-identity identity.systemError error',
        level: 'error'
    },
    {
        name: 'identity.throttleError',
        defaultMessage: 'After several attempts, the registration has been locked, please start again in 60 min.',
        level: 'error'
    },
    {
        name: 'identity.throttleErrorForgotten',
        defaultMessage: 'After several attempts, the password change has been locked, please start again in 60 min.',
        level: 'error'
    }
].reduce(function(prev, next) {
    var spec = next.name.split('.');
    var Ctor = create(spec.pop(), spec.join('.'), next.defaultMessage, next);
    prev[next.name] = function(params) {
        return new Ctor({params: params});
    };
    return prev;
}, {});
