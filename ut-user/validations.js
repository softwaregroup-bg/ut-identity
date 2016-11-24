'use strict';
var joi = require('joi');

module.exports = {
    'check': {
        description: 'identity check',
        notes: ['identity check'],
        tags: ['identity'],

        params: joi.object({
            username: joi.string(),
            timezone: joi.string(),
            uri: joi.string(),
            bio: joi.array().items(
                joi.object().keys({
                    finger: joi.string().valid(['L1', 'L2', 'L3', 'L4', 'L5', 'R1', 'R2', 'R3', 'R4', 'R5']).required(),
                    templates: joi.array().items(joi.string()).required()
                })
            ),
            otp: joi.string().allow(''),
            registerPassword: joi.string(),
            forgottenPassword: joi.string(),
            newPassword: joi.string(),
            password: joi.string().allow('').min(1)
        }),
        result: joi.any(),

        auth: false,
        route: '/login'
    },
    'closeSession': {
        description: 'identity cleanup',
        notes: ['identity cleanup'],
        tags: ['identity'],

        params: joi.object({
            sessionId: joi.string().min(1)
        }),
        result: joi.any()
    },
    'forgottenPassword': {
        description: 'forgotten password',
        notes: ['forgotten password'],
        tags: ['identity'],

        params: joi.object({}),
        result: joi.any(),

        auth: false,
        route: '/forgottenPassword',
        paramsMethod: ['identity.forgottenPassword', 'identity.forgottenPasswordRequest', 'identity.forgottenPasswordValidate']
    },
    'registerRequest': {
        description: 'register request',
        notes: ['register request'],
        tags: ['identity'],

        params: joi.object({
            countryCode: joi.string().min(2).max(3),
            phoneNumber: joi.string().min(1),
            language: joi.string().min(2).max(2),
            dateOfBirth: joi.string().min(10),
            uri: joi.string().min(1),
            username: joi.string().min(1).required()
        }),
        result: joi.any(),

        auth: false,
        route: '/register',
        paramsMethod: ['identity.registerRequest', 'identity.registerValidate']
    },
    'changePassword': {
        description: 'change Password',
        params: joi.object(),
        result: joi.any()
    }
};
