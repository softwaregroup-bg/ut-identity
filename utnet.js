var bus = {};
var log = {};
var utTemplate = require('ut-template');
var _ = require('lodash');
var templates = null;
var fs = require('fs');

module.exports = function(templates) {
    templates = _.assign({
        check: utTemplate.load(require.resolve('./utnet/check.sql.marko'))
    }, templates);

    return {
        init: function(b) {
            bus = b;
            log = bus.logFactory.createLog('warn', {name: 'ut', context: 'identity'});
        },
        initRoutes: function() {
            bus.importMethod('internal.registerRequestHandler')({
                method: 'GET',
                path: '/identity/{method}',
                config: {
                    handler: function(request, reply) {
                        var file = '../ut-identity/browser/html/index.html';
                        fs.exists(file, function(valid) {
                            fs.readFile(file, function(err, data) {
                                if (err) throw err;
                                reply(data.toString());
                            });
                        });
                    }
                }
            });
            bus.importMethod('internal.registerRequestHandler')({
                method: 'GET',
                path: '/s/identity/{p*}',
                handler: {
                    directory: {
                        path: __dirname,
                        listing: false,
                        index: true
                    }
                }
            });
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
                        auth.sessionId = loginResult['a:Session'];
                        return auth;
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


