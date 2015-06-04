var bus = {};
var log = {};
var utTemplate = require('ut-template');
var triggerError = require('../impl-ifinance/helpers').triggerError; // TODO fix this
var _ = require('lodash');
var templates = null;

function login(auth, templates, self) {
    var promise = null;
    var lang = auth.language;
    if (auth.fingerPrint) {
        if (auth.customerNo) {
            return bus.importMethod('bio.verifyClient')({
                fingerPrint: auth.fingerPrint
            });
        } else {
            promise = bus.importMethod('bio.biometricsLogin')({
                fingerPrint: auth.fingerPrint
            }).then(function(response) {
                return this.execTemplateRow(templates.getUserProfile, auth);
            }.bind(this));
            if (auth.sessionData) {
                return promise.then(function(response) {
                    return this.execTemplateRow(templates.setActiveUserSession, auth);
                });
            } else {
                return promise;
            }
        }
    } else if (auth.username && auth.password) {
        promise = self.execTemplateRow(templates.credentialsLogin, auth)({
            username: auth.username,
            password: auth.password
        })
        if (auth.sessionData) {
            return promise.then(function(response) {
                return this.execTemplateRow(templates.setActiveUserSession, auth);
            }.bind(this));
        } else {
            return promise;
        }
    } else {
        triggerError(null, lang, error);
    }
};

module.exports = function(templates) {
    templates = _.assign({
        check: utTemplate.load(require.resolve('./utnet/utNet_check.sql.marko')),
        changeUserPassword: utTemplate.load(require.resolve('./utnet/changeUserPassword.sql.marko')),
        changeUserPassword: utTemplate.load(require.resolve('./utnet/changeUserPassword.sql.marko')),
        reloadSession: utTemplate.load(require.resolve('./utnet/reloadSession.sql.marko')),
        updateSession: utTemplate.load(require.resolve('./utnet/updateSession.sql.marko'))
    }, templates);

    return {
        init: function(b) {
            bus = b;
            log = bus.logFactory.createLog('warn', {name: 'identity', context: 'check'});
        },
        check: function(auth) {
            auth = auth.$$.authentication;
            auth.implementationID = bus.config.implementation || '';
            return this.execTemplateRow(templates.check, auth).then(function(response) {
                return response;
            }).catch(function(error) {
                return error;
            });
            /*
            if (auth.sessionId) {
                return this.execTemplateRow(templates.sessionLogin, auth)({
                    sessionId: auth.sessionId
                }).then(function(response) {

                }).catch(function() {
                    return login(auth, templates, this);
                });
            } else {
                return login(auth, templates, this);
            }
            */
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


