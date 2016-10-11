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
            bio: joi.string().allow(''),
            otp: joi.string().allow(''),
            registerPassword: joi.string(),
            newPassword: joi.string(),
            password: joi.string().allow('').min(1)
        }),
        auth: false,
        route: '/login',
        result: joi.any()
    }
};
