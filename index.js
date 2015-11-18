var utTemplate = require('ut-template');
var crypto = require('crypto');
var _ = require('lodash');
function getHash(user, pass) {
    var md5 = crypto.createHash('md5').update('SoftwareGroupBG', 'utf8');
    md5.update(pass, 'utf8');
    md5.update(user, 'utf8');
    return md5.digest('hex').toString('hex').toUpperCase();
}
module.exports = function(templates) {
    templates = _.assign({
        check:utTemplate.load(require.resolve('./ut/check.sql.marko')),
        closeSession:utTemplate.load(require.resolve('./ut/closeSession.sql.marko')),
        invalidateSession:utTemplate.load(require.resolve('./ut/invalidateSession.sql.marko')),
        changePassword:utTemplate.load(require.resolve('./ut/changePassword.sql.marko'))
    }, templates || {});

    function getParams(params) {
        var config =  _.assign({ // merge only once
            'sessionTimeout'        : 600,
            'singleUserSession'     : 'false',
            'module'                : 'ut5',
            'language'              : 'EN',
            'remoteIp'              : null,
            'implementation'        : 'default',
            'userAgent'             : null,
            'checkUserRightsIp'     : 'true',
            'createSession'         : 'true'
        }, (this.config && this.config.identity) || {});
        getParams = function(params) { // lazy initialization
            params.random = Math.random().toString(36).substring(5).toUpperCase();
            if (params.password) {
                params.passwordHash = getHash(params.username, params.password);
            }
            if (params.passwordNew) {
                params.passwordHashNew = getHash(params.username, params.passwordNew);
            }
            return _.defaults(params, config);
        }
        return getParams(params);
    }
    return {
        check: function(params) {
            params.password = getHash(params.username, params.password);
            return this.execTemplateRow(templates.check, getParams.call(this, params)).then(function(result){
                if(this.bus.config && this.bus.config.checkPermission) {
                    return this.bus.importMethod('permission.getPermissions')(result)
                        .then(function(permissions){
                            result.permissions = permissions;
                            return result;
                        });
                } else {
                    return result;
                }
            }.bind(this));
        },
        closeSession: function(params) {
            return this.execTemplateRow(templates.closeSession, params);
        },
        invalidateSession: function(params) {
            return this.execTemplateRow(templates.invalidateSession, getParams.call(this, params));
        },
        changePassword: function(params) {
            params.passwordHash = getHash(params.username, params.password);
            return this.execTemplateRow(templates.changePassword, params);
        },
        getHash: function(params) {
            return getHash(params.username, params.password);
        }
    };
};
