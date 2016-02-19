var err = require('ut-error');
var create = err.define;

var Identity = create('identity');
var Crypt = err.get('identity.crypt', Identity);
var MultipleResults = create('identity.multipleResults', Identity);


module.exports = {
    multipleResults: function(params) {
        return new MultipleResults({message: 'Database returned multiple results', params: params});
    },
    crypt: function(msg, params) {
        return new Crypt({message: msg, params: params});
    }
};
