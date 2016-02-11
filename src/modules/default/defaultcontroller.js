export default function DefaultController($auth, ProfileService, github) {
  this.title = "Welcome to the github explorer";
  
  this.token = localStorage.getItem('token');
  
    this.onAuthenticated = function(){
        ProfileService.getProfile().then((response)=>{
        
            this.user = github.SimpleUser(response.data);
            
            ProfileService.repos().then((response)=>{
                console.log(response.data); 
                
                ProfileService.skills().then((response)=>{
                    console.log(response.data);
                })
            });
        });
    } 
  
  if(this.token){
      this.onAuthenticated();
  }

  this.authenticate = function(provider){
      
      $auth.authenticate(provider)
        .then((response)=>{
            this.token = response.data.token;
            localStorage.setItem('token', response.data.token);
            
            this.onAuthenticated();
        })

      .catch(function(response){
          //TODO replace with a decent error message
          console.log("Error occured while trying to connect to github");
      });
  }
  
  this.disconnect = function(){
      localStorage.removeItem('token');
      
      this.token = undefined;
  }
}