export class ApiError extends Error {
  constructor(
    statusCode,
    data=null,
    message = "Something Went Wrong",
    errors = [],
    stack = ""
  ) {
    super(message) // calling constructor of parentClass
    this.statusCode = statusCode;
    this.data=data;
    this.message = message;
    this.success=false;
    this.errors=errors
    if(stack){
        this.stack =stack } 
    else{
        Error.captureStackTrace(this, this.constructor);
    }    
    
 
  }
}
