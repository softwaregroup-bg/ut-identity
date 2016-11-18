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
            bio: joi.array().items(
                joi.object().keys({
                    finger: joi.string().valid(['L1', 'L2', 'L3', 'L4', 'L5', 'R1', 'R2', 'R3', 'R4', 'R5']).required(),
                    templates: joi.array().items(joi.string()).required()
                })
            ),
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
