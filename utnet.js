var utTemplate = require('ut-template');
var _ = require('lodash');

module.exports = function(templates) {
    templates = _.assign({
        check:utTemplate.load(require.resolve('./utnet/check.sql.marko')),
        closeSession:utTemplate.load(require.resolve('./utnet/closeSession.sql.marko')),
        invalidateSession:utTemplate.load(require.resolve('./utnet/invalidateSession.sql.marko')),
        changePassword:utTemplate.load(require.resolve('./utnet/changePassword.sql.marko'))
    }, templates);

    return {
        check: function(auth) {
            return this.execTemplateRow(templates.check, auth);
        },
        closeSession: function(criteria) {
            return this.execTemplateRow(templates.closeSession, criteria);
        },
        invalidateSession: function(criteria) {
            return this.execTemplateRow(templates.invalidateSession, criteria);
        },
        changePassword: function(auth) {
            return this.execTemplateRow(templates.changePassword, auth);
        }
    };
};
