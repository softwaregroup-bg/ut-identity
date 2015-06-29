var module = angular.module('ut-identity', ['ngRoute', 'ngCookies']);
module.config(function($routeProvider, $locationProvider) {
    $locationProvider.html5Mode({ enabled: true, requireBase: false });
    $routeProvider.when('/identity/check', {
        templateUrl: '/s/identity/browser/html/check.html',
        controller: 'IdentityController'
    }).otherwise({
        redirectTo: '/identity/check'
    })
});
module.factory('ut', function($q, $http, $cookies) {
    var request = {
        jsonrpc: '2.0',
        id: 122,
        auth: {},
        params: {}
    };
    return {
        'identity.check': function(auth) {
            request.method = 'identity.check';
            request.auth = auth;
            return $http.post('/rpc', request).then(function(response) {
                if (response.data.result) {
                    $cookies.put('sessionId', response.data.result.sessionId);
                    var fallbackUrl = $cookies.get('fallbackUrl') || '/';
                    return response.data.result;
                } else if (response.data.error) {
                    throw new Error(response.data.error.message);
                } else {
                    throw new Error('UnidentifiedError');
                }
            }).catch(function(error) {
                throw error;
            });
        }
    }
});
module.controller('IdentityController', function($scope, $routeParams, $http, $cookies, $window, ut) {
    var fallbackUrl;
    $scope.user = {};
    $scope.submit = function() {
        ut['identity.check']({
            username: this.username,
            password: this.password
        }).then(function(response) {
            if (response.Result && parseInt(response.Result) == 0) {
                fallbackUrl = $cookies.get('fallbackUrl') || '/';
                $window.location.href = $window.location.protocol + '//' + $window.location.host + fallbackUrl;
            } else {
                alert('IdentityError');
            }
        }).catch(function(error) {
            alert('IdentityError');
        })
    }
});