var bus = {};
var log = {};
var utTemplate = require('ut-template');
var _ = require('lodash');
var templates = null;

module.exports = function(templates) {
    templates = _.assign({
        check: utTemplate.load(require.resolve('./utnet/check.sql.marko'))
    }, templates);

    return {
        init: function(b) {
            bus = b;
            log = bus.logFactory.createLog('warn', {name: 'ut', context: 'identity'});
        },
        check: function(auth) {
            if (auth.fingerPrint) {
                if (auth.customerNo) {
                    return bus.importMethod('bio.verifyClient')({
                        fingerPrint: auth.fingerPrint,
                        sessionId: auth.sessionId
                    }).then(function(response) {
                        if (response.customerNo == auth.customerNo) {
                            return {isVerified: true};
                        } else {
                            return {isVerified: false};
                        }
                    }).catch(function(error) {
                        throw new Error('BioVerificationError');
                    });
                } else {
                    return bus.importMethod('bio.biometricsLogin')({
                        fingerPrint: auth.fingerPrint
                    }).then(function(response) {
                        auth.userId = response.userId;
                        return this.execTemplateRow(templates.check, auth);
                    }).catch(function(error) {
                        throw new Error('BioLoginError');
                    });
                }
            } else {
                return this.execTemplateRow(templates.check, auth);
            }
        },
        closeSession: function(criteria) {
            return this.execTemplateRow(templates.deleteActiveUserSession, criteria);
        },
        relaodSession: function(criteria) {
            return this.execTemplateRow(templates.reloadSession, criteria);
        },
        changePassword: function(auth) {
            return this.execTemplateRow(templates.changeUserPassword, auth);
        },
        updateSession: function(msg) {
            return this.execTemplateRow(templates.updateSession, auth);
        },
    };
};

require('./validation.utnet')(module.exports);


