export default function DefaultController($auth, ProfileService, github) {
  this.title = "Welcome to the github explorer";
  
  this.token = localStorage.getItem('token');
  
  if(this.token){
    ProfileService.getProfile().then((response)=>{
        this.user = github.SimpleUser(response.data);
    });
  }
  
  this.authenticate = function(provider){
      
      $auth.authenticate(provider)
        .then((response)=>{
            this.token = response.data.token;
            localStorage.setItem('token', response.data.token);
            
            ProfileService.getProfile().then((response)=>{
                this.user = github.SimpleUser(response.data);
            });
        })

      .catch(function(response){
          //TODO replace with a decent error message
          console.log("Error occured while trying to connect to github");
      });
  }
}