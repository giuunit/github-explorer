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
}