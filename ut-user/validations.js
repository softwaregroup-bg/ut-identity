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

            uri: joi.string(),
            otp: joi.string().allow(''),
            password: joi.string().allow('').min(1)
        }),
        auth: false,
        route: '/login',
        result: joi.any()
    }
};
