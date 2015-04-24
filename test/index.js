var identity = require('../');
var errors = require('../errors')
var chai = require("chai");
var chaiAsPromised = require("chai-as-promised");

chai.use(chaiAsPromised);
var expect=chai.expect;

describe('identity.check', function() {
    it('Should succeed with valid password', function() {
        return expect(identity.check({username:'test',password:'valid'})).to.eventually.have.property('userId');
    });
    it('Should fail with invalid password', function() {
        return expect(identity.check({username:'test',password:'invalid'})).to.be.rejectedWith(errors.InvalidCredentials);
    });
    it('Should detect expired password', function(){
        return expect(identity.check({username:'test',password:'expired'})).to.be.rejectedWith(errors.ExpiredPassword);
    });
    it('Should succeed with valid fingerprint', function() {
        return expect(identity.check({fingerPrint:'valid'})).to.eventually.have.property('userId');
    });
    it('Should fail with invalid fingerprint', function() {
        return expect(identity.check({fingerPrint:'invalid'})).to.be.rejectedWith(errors.InvalidFingerprint);
    });
    it('Should succeed with valid session', function() {
        return expect(identity.check({sessionId:'valid'})).to.eventually.have.property('userId');
    });
    it('Should fail with invalid session', function() {
        return expect(identity.check({sessionId:'invalid'})).to.be.rejectedWith(errors.SessionExpired);
    });
    it('Should fail with missing credentials', function() {
        return expect(identity.check({userId:1})).to.be.rejectedWith(errors.MissingCredentials);
    });
    it('Should fail when credentials wre not passed', function() {
        return expect(identity.check()).to.be.rejectedWith(errors.MissingCredentials);
    });
})
