import {validationResult } from 'express-validator'
import { ApiError } from '../utils/apiError.js'

export const validate =(req,res,next)=>{
    const errors  = validationResult(req)  //   validationResult() extracts errors from req
    //lets check if there is any incoming errors
    if(errors.isEmpty()){
        return next()
    }

    //lets make an array ,so we can push errors on it

    const extractedErrors  = []
    errors.array().map((err)=>extractedErrors.push({[err.path]:err.msg}))
    

    //Explaination
/* extractedErrors.push({ [err.path]: err.msg })

This part is the real trick.

{ [err.path]: err.msg } is a computed property name in JavaScript.

If err.path = "email" and err.msg = "Email is invalid", then:

{ email: "Email is invalid" }  */


throw new ApiError(422,"Received data is not Valid or in format",extractedErrors)

}