var module = angular.module('ut-identity', ['ngRoute', 'ngCookies']);
module.config(function($routeProvider, $locationProvider) {
    $locationProvider.html5Mode({ enabled: true, requireBase: false });
    $routeProvider.when('/identity/check', {
        templateUrl: '/s/user/browser/html/check.html',
        controller: 'IdentityController'
    }).otherwise({
        redirectTo: '/identity/check'
    })
});