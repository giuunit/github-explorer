import angular from './lib/';

import './modules/default/';
import routes from './routes';
import oauth from './oauth'
import 'angular-route';
import 'satellizer';

angular.module('gitEx', ['ngRoute', 'default' , 'satellizer'])
   .config(routes)
   .config(oauth);

document.addEventListener('DOMContentLoaded', () => {
  angular.bootstrap(document.body, ['gitEx']);
});