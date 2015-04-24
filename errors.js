var err = require('errno');
var when = require('when');
var IdentityError = err.create('IdentityError');

module.exports = {
    MissingCredentials: err.create('MissingCredentials',IdentityError),
    InvalidCredentials: err.create('InvalidCredentials',IdentityError),
    ExpiredPassword: err.create('ExpiredPassword',IdentityError),
    SessionExpired: err.create('SessionExpired',IdentityError),
    InvalidFingerprint: err.create('InvalidFingerprint',IdentityError),
    IdentityError: IdentityError
}

Object.getOwnPropertyNames(module.exports).forEach(function(key){
    var method = module.exports[key];
    method.reject = function(){
        return when.reject(new method(arguments)); //todo improve arguments passing
    }
})

