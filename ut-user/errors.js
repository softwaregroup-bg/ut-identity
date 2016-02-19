var create = require('ut-error').define;

var Identity = create('identity');
var Crypt = create('crypt', Identity);
var MultipleResults = create('multipleResults', Identity);


module.exports = {
    multipleResults: function(params) {
        return new MultipleResults({message: 'Database returned multiple results', params: params});
    },
    crypt: function(msg, params) {
        return new Crypt({message: msg, params: params});
    }
};
