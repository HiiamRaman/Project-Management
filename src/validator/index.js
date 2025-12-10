
import { body } from "express-validator";



export const userRegisterValidator = () => {
  return [

      body("email")
        .trim()
        .notEmpty()
        .withMessage("Email is required!!")
        .isEmail()
        .withMessage("invalid Email"),
      body("username")
        .trim()
        .notEmpty()
        .withMessage("Username is required!! ")
        .isLowercase()
        .withMessage("username must be in lower case")
        .isLength()
        .withMessage("username must have at least 3 characters"),
        body("password")
        .trim()
        .notEmpty()
        .withMessage("password is required!!"),
        body("fullname")
        .optional()
        .trim(),
        body("role")
        .optional()
        .default("member")
        .isIn(["admin","member","adminstrator"])
        .withMessage("invalid role")
      
]

};

export const userLoginValidator = ()=>{
  return [
    body("email")
    .optional()
    .isEmail()
    .withMessage("Invalid email!!"),
    body("password")
     .notEmpty()
     .withMessage("Password is Required")
  ]
}
