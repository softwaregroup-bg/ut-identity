var create = require('ut-error').define;

var Identity = create('identity');
var Crypt = create('crypt', Identity);
var NotImplemented = create('notImplemented', Identity);
var NothingForValidation = create('nothingForValidation', Identity);
var MultipleResults = create('multipleResults', Identity);

module.exports = {
    multipleResults: function(params) {
        return new MultipleResults({message: 'Database returned multiple results', params: params});
    },
    nothingForValidation: function(params) {
        return new NothingForValidation({message: 'App cannot determine wich valudation type is required', params: params});
    },
    crypt: function(msg, params) {
        return new Crypt({message: msg, params: params});
    },
    notImplemented: function(msg, params) {
        return new NotImplemented({message: 'This method is not yet implemented', params: params});
    }
};
