export default class Github {
    constructor(){
        this.SimpleUser = (obj) => new SimpleUser(obj); 
    }
}

//private class, accessible only in the github class
class SimpleUser {
    constructor(obj){
        this.displayName = obj.displayName;
        this.github = obj.github;
        this.picture = "https://avatars.githubusercontent.com/u/" + obj.github;
    }
}
