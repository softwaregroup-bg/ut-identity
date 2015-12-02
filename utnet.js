var bus;
var utTemplate = require('ut-template');
var _ = require('lodash');

module.exports = function(templates) {
    templates = _.assign({
        check: utTemplate.load(require.resolve('./utnet/check.sql.marko')),
        closeSession: utTemplate.load(require.resolve('./utnet/closeSession.sql.marko'))
    }, templates);

    return {
        init: function(b) {
            bus = b;
        },
        check: function(auth) {
            if (auth.fingerPrint) {
                if (auth.customerNo && auth.session.id) {
                    return bus.importMethod('bio.verifyClient')({
                        fingerPrint: auth.fingerPrint,
                        sessionId: auth.session.id
                    }).then(function(response) {
                        return {customerNo: response.customerNo};
                    }).catch(function() {
                        throw new Error('BioVerificationError');
                    });
                } else {
                    return this.bus.importMethod('bio.biometricsLogin')({
                        fingerPrint: auth.fingerPrint
                    }).then(function(response) {
                        auth.userId = response.userId;
                        auth.session.id = response.sessionId;
                        return auth;
                    }).catch(function(error) {
                        throw error;
                    });
                }
            } else {
                return this.execTemplateRow(templates.check, auth).then(function(response) {
                    if (response.Result === 0 || response.Result === '0') {
                        auth.userId = response.userId;
                        auth.session.id = response.sessionId;
                        return auth;
                    } else {
                        var err = new Error(response.ResultMessage);
                        err.code = response.ResultMessage;
                        err.errorPrint = response.ResultMessage;
                        throw err;
                    }
                }).catch(function(error) {
                    throw error;
                });
            }
        },
        closeSession: function(criteria) {
            return this.execTemplateRow(templates.closeSession, criteria);
        },
        relaodSession: function(criteria) {
            return this.execTemplateRow(templates.reloadSession, criteria);
        },
        changePassword: function(auth) {
            return this.execTemplateRow(templates.changeUserPassword, auth);
        },
        updateSession: function(msg) {
            return this.execTemplateRow(templates.updateSession);
        }
    };
};
