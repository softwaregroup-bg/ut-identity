var identity = require('../api');
var errors = require('../errors');

var test = require('blue-tape');

test('Should succeed with valid password', function(t) {
    return identity.check({username: 'test', password: 'valid'}).then((result) => {
        t.ok(result.userId, 'return userId');
        return t.end();
    });
});

test('Should fail with invalid password', function(t) {
    t.same(identity.check({username: 'test', password: 'invalid'}), errors['identity.invalidCredentials']());
    return t.end();
});

test('Should detect expired password', function(t) {
    t.same(identity.check({username: 'test', password: 'expired'}), errors['identity.expiredPassword']());
    return t.end();
});

test('Should succeed with valid fingerprint', function(t) {
    return identity.check({fingerPrint: 'valid'}).then((result) => {
        t.ok(result.userId, 'return userId');
        return t.end();
    });
});

test('Should fail with invalid fingerprint', function(t) {
    t.same(identity.check({fingerPrint: 'invalid'}), errors['identity.invalidFingerprint']());
    return t.end();
});

test('Should succeed with valid session', function(t) {
    return identity.check({sessionId: 'valid'}).then((result) => {
        t.ok(result.userId, 'return userId');
        return t.end();
    });
});

test('Should fail with invalid session', function(t) {
    t.same(identity.check({sessionId: 'invalid'}), errors['identity.sessionExpired']());
    return t.end();
});

test('Should fail with missing credentials', function(t) {
    t.same(identity.check({userId: 1}), errors['identity.missingCredentials']());
    return t.end();
});

test('Should fail when credentials were not passed', function(t) {
    t.same(identity.check(), errors['identity.missingCredentials']());
    return t.end();
});
