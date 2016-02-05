export default function RouteConfig($routeProvider) {
  $routeProvider
     .when('/', {
        templateUrl: './modules/default/default.html',
        controller: 'DefaultController',
        controllerAs: 'default'
     })
     .when('/callback:id',{
        templateUrl: './modules/callback/callback.html',
     })
     .when('/auth/github',{
         controller: 'OAuthController'
     })
     .otherwise({
        templateUrl: './modules/default/default.html',
        controller: 'DefaultController',
        controllerAs: 'default'
     });;
}