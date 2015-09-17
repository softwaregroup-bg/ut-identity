var errors = require('./errors');
var when = require('when');

module.exports = {
    check : function(auth) {
        if (auth) {
            if (auth.username && auth.password && auth.username.length && auth.password.length) {
                if (auth.username === 'test' && auth.password === 'valid') {
                    // if sessionId is invalid, create a new session
                    var sessionData = auth.sessionData || {};
                    sessionData.userId = 1;
                    sessionData.sessionId = 'valid';
                    return when.resolve(sessionData);
                } else if (auth.username === 'test' && auth.password === 'expired') {
                    return errors.ExpiredPassword.reject();
                } else {
                    return errors.InvalidCredentials.reject();
                }
            } else if (auth.fingerPrint) {
                if (auth.fingerPrint === 'valid') {
                    return when.resolve({userId:1});
                } else {
                    return errors.InvalidFingerprint.reject();
                }
            } else if (auth.sessionId) {
                if (auth.sessionId === 'valid') {
                    return when.resolve({userId:1});
                } else {
                    return errors.SessionExpired.reject();
                }
            } else {
                return errors.MissingCredentials.reject();
            }
        }
        return errors.MissingCredentials.reject();
    },
    closeSession : function(criteria) {

    },
    invalidateSession : function(criteria) {

    },
    changePassword : function(auth) {

    }
};
