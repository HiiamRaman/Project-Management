
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
        body("passwrod")
        .trim()
        .notEmpty()
        .withMessage("password is required!!"),
        body("fullname")
        .optional()
        .trim()
]

  
};
