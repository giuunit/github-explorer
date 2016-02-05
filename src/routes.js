export default function RouteConfig($routeProvider, $locationProvider) {
  $routeProvider
    .when('/', {
        templateUrl: './modules/default/default.html',
        controller: 'DefaultController',
        controllerAs: 'default'
    })
    .when('/auth/:provider',{
        controller: 'OAuthController',
        templateUrl: './modules/auth/auth.html',
    })
    .otherwise({
        redirectTo: '/'
    });
}