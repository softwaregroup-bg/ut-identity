'use strict';

/**
 * Returns user-friendly translated error message as string
 * E.g.: Your password must contains: a lowercase letter, an uppercase letter, a digit, a special character (@, #, &, etc.)
 *
 * @param {Object[]} itemsTranslation
 * @param {string} errorString
 * @param {number} minLength
 * @param {number} maxLength
 */
var buildPolicyErrorMessage = function(itemsTranslation, errorString, minLength, maxLength) {
    // build translation object
    var translationObject = {};
    for (var i = 0; i < itemsTranslation.length; i += 1) {
        var currentItemTranslation = itemsTranslation[i];
        translationObject[currentItemTranslation.itemCode] = currentItemTranslation.itemNameTranslation;
    }

    var getTranslationString = function(string) {
        if (translationObject[string]) {
            return translationObject[string];
        } else {
            return string;
        }
    };

    // build error message for lenght
    var errorMessage = getTranslationString('Your password must be between') + ' ';
    errorMessage += minLength + ' ' + getTranslationString('and') + ' ' + maxLength + ' characters long';

    // build error message for regex
    errorMessage += ' ' + getTranslationString('and') + ' ' + getTranslationString('must contain') + ': ';
    var splittedErrorString = errorString.split(',');
    var mappedErrorStrings = splittedErrorString.map((errString) => {
        return getTranslationString(errString);
    });
    errorMessage += mappedErrorStrings.join(', ');
    return errorMessage;
};

module.exports = {
    buildPolicyErrorMessage
};
