export default function DefaultController($auth) {
  this.title = "Welcome to the github explorer, please authenticate";
  
  this.authenticate = function(provider){
      
      $auth.authenticate(provider)
        .then(function(response){
          console.log(response);
      })
      .catch(function(response){
          console.log(response);
      });
  }
}