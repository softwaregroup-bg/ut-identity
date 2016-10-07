'use strict';
var joi = require('joi');

module.exports = {
    'check': {
        description: 'identity check',
        notes: ['identity check'],
        tags: ['identity'],
        params: joi.object({
            uri: joi.string(),
            username: joi.string().required(),
            timezone: joi.string().required(),
            password: joi.string().min(1)
        }),
        auth: false,
        route: '/login',
        result: joi.any()
    }
};
