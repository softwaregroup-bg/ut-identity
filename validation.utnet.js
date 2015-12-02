var joi = require('joi');
var tags = ['api', 'identity'];
var validation = {
    check: {
        tags: tags,
        request: {
            asdasdas: joi.string().required()
        },
        response: {

        }
    }
};

module.exports = function(module, ns) {
    var _ = require('lodash');
    Object.keys(module).forEach(function(value) {
        _.assign(module[value], ns ? validation[ns][value] : validation[value]);
    });
};
