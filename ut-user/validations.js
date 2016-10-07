'use strict';
var joi = require('joi');

module.exports = {
    'check': {
        description: 'identity check',
        notes: ['identity check'],
        tags: ['identity'],
        params: joi.object({
            username: joi.string().required(),
            timezone: joi.string().required(),
            password: joi.string().min(1)
        }),
        auth: false,
        anotherRoute: '/login',
        result: joi.any()
    }
};
