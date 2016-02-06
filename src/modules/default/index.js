import 'angular';
import DefaultController from './defaultcontroller';
import ProfileService from '../../services/profile';
import github from '../../lib/github/';

angular.module('default',[])
   .controller('DefaultController', DefaultController)
   .service('ProfileService', ProfileService)
   .service('github', github);
