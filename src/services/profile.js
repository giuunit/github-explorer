export default function ProfileService($http){
    this.getProfile = function() {
        return $http.get('/api/me');
    }

    this.updateProfile = function(profileData) {
        return $http.put('/api/me', profileData);
    }
    
    this.details = function(){
        return $http.get('/api/details');
    }
    
    this.repos = function(){
        return $http.get('/api/repos');
    }
    
    this.skills = function(){
        return $http.get('/api/skills');
    }
}