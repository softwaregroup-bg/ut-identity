var err = require('ut-error');
var create = err.define;

var PortSQL = err.get('PortSQL');
var Crypt = err.get('Crypt');
var MissingResultset = create('MissingResultset', PortSQL);
var MultipleResults = create('MultipleResults', PortSQL);


module.exports = {
    missingResultset: function(params) {
        return new MissingResultset({message: 'Missing resultset', params: params});
    },
    multipleResults: function(params) {
        return new MultipleResults({message: 'Database returned multiple results', params: params});
    },
    crypt: function(msg, params) {
        return new Crypt({message: msg, params: params});
    }
};
