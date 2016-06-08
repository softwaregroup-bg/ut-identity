var assign = require('lodash.assign');
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
    Object.keys(module).forEach(function(value) {
        assign(module[value], ns ? validation[ns][value] : validation[value]);
    });
};
