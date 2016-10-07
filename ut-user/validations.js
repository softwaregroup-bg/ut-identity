'use strict';
var joi = require('joi');

module.exports = {
    'check': {
        description: 'identity check',
        notes: ['identity check'],
        tags: ['identity'],
        params: joi.object({
            username: joi.string().required()
        }),
        result: joi.any()
    }
};
