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
            password: joi.string().allow('').min(1),
            channel: joi.string().valid(['web', 'mobile']).required()
        }),
        result: joi.object().keys({
            'identity.check': joi.object().keys({
                sessionId: joi.string().required(),
                actorId: joi.number().integer().required(),
                cookie: joi.string().required(),
                language: joi.string().required(),
                module: joi.string().allow('').allow(null).required(),
                remoteIP: joi.string().allow(null).required(),
                userAgent: joi.string().allow('').allow(null).required(),
                expire: joi.date().required(),
                dateCreated: joi.date().required()
            }),
            'permission.get': joi.array().items({
                actionId: joi.string().required(),
                objectId: joi.string().required(),
                description: joi.string().required()
            }),
            person: joi.object().keys({
                actorId: joi.number().integer().required(),
                frontEndRecordId: joi.string().allow(null).required(),
                firstName: joi.string().required(),
                lastName: joi.string().required(),
                nationalId: joi.string().allow(null),
                dateOfBirth: joi.date().allow(null),
                placeOfBirth: joi.string().allow(null),
                nationality: joi.string().allow(null),
                gender: joi.string().allow(null),
                bioId: joi.string().allow(null),
                oldValues: joi.string().allow(null),
                udf: joi.string().allow(null),
                phoneModel: joi.string().allow(null),
                computerModel: joi.string().allow(null),
                isEnabled: joi.boolean().allow(0, 1, '0', '1'),
                isDeleted: joi.boolean().allow(0, 1, '0', '1'),
                maritalStatusId: joi.string().allow(null),
                age: joi.number().integer().allow(null)
            }),
            language: joi.object().keys({
                languageId: joi.number().required(),
                iso2Code: joi.string().required(),
                name: joi.string().required(),
                locale: joi.string().required()
            }),
            localisation: joi.object().keys({
                dateFormat: joi.string().allow(null),
                numberFormat: joi.string().allow(null)
            }),
            roles: joi.array(),
            emails: joi.array(),
            screenHeader: joi.object().keys({
                fieldOfWorkId: joi.string(),
                fieldOfWork: joi.string(),
                itemCode: joi.string()
            }).allow(null),
            loginFactors: joi.array().items({
                type: joi.string(),
                params: joi.string().allow(null),
                allowedAttempts: joi.number().integer()
            }).optional()
        }),

        auth: false,
        route: '/login'
    },
    'closeSession': {
        description: 'identity cleanup',
        notes: ['identity cleanup'],
        tags: ['identity'],

        params: joi.object({
            sessionId: joi.string()
        }),
        result: joi.array()
    },
    'forgottenPassword': {
        description: 'forgotten password',
        notes: ['forgotten password'],
        tags: ['identity'],

        params: joi.object(),
        result: joi.array(),

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
            username: joi.string().min(1).required(),
            registerPassword: joi.string()
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
