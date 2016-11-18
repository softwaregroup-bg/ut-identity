var identity = require('../api');
var errors = require('../errors');

var test = require('blue-tape');

test('Should succeed with valid password', function(t) {
    return identity.check({username: 'test', password: 'valid'}).then((result) => {
        t.ok(result.userId, 'return userId');
        return;
    });
});

test('Should fail with invalid password', function(t) {
    return t.shouldFail(identity.check({username: 'test', password: 'invalid'}), errors.InvalidCredentials);
});

test('Should detect expired password', function(t) {
    return t.shouldFail(identity.check({username: 'test', password: 'expired'}), errors.ExpiredPassword);
});

test('Should succeed with valid fingerprint', function(t) {
    return identity.check({fingerPrint: 'valid'}).then((result) => {
        t.ok(result.userId, 'return userId');
        return;
    });
});

test('Should fail with invalid fingerprint', function(t) {
    return t.shouldFail(identity.check({fingerPrint: 'invalid'}), errors.InvalidFingerprint);
});

test('Should succeed with valid session', function(t) {
    return identity.check({sessionId: 'valid'}).then((result) => {
        t.ok(result.userId, 'return userId');
        return;
    });
});

test('Should fail with invalid session', function(t) {
    return t.shouldFail(identity.check({sessionId: 'invalid'}), errors.SessionExpired);
});

test('Should fail with missing credentials', function(t) {
    return t.shouldFail(identity.check({userId: 1}), errors.MissingCredentials);
});

test('Should fail when credentials were not passed', function(t) {
    return t.shouldFail(identity.check(), errors.MissingCredentials);
});
