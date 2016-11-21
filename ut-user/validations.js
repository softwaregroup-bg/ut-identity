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
            bio: joi.string().allow(''),
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

        params: joi.object({}),
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

        params: joi.object({}),
        result: joi.any(),

        auth: false,
        route: '/register',
        paramsMethod: ['identity.registerRequest', 'identity.registerValidate']
    }
};
