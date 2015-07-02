var bus = {};
var log = {};
var utTemplate = require('ut-template');
var _ = require('lodash');
var templates = null;
var fs = require('fs');

module.exports = function(templates) {
    templates = _.assign({
        check: utTemplate.load(require.resolve('./utnet/check.sql.marko')),
        closeSession: utTemplate.load(require.resolve('./utnet/closeSession.sql.marko'))
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
                        sessionId: auth.session.id
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
                    return this.bus.importMethod('bio.biometricsLogin')({
                        fingerPrint: auth.fingerPrint
                    }).then(function(res) {
                        var loginResult = res.payload.BiometricsLoginResponse.BiometricsLoginResult;
                        if (loginResult['a:Result'] == 'false' || loginResult['a:UserID'] == '0') {
                            var er = new Error();
                            er.code = '2002';
                            er.message = 'fingerPrint login failed';
                            er.errorPrint = 'Invalid fingerprint';
                            throw er;
                        }
                        auth.userId = loginResult['a:UserID'];
                        auth.session.id = loginResult['a:Session'];
                        return auth;
                    });
                }
            } else {
                return this.execTemplateRow(templates.check, auth);
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
            return this.execTemplateRow(templates.updateSession, auth);
        },
    };
};

require('./validation.utnet')(module.exports);


