export const userRegisterValidator = () => {
  return [body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required!!")
    .isEmail()
    .withMessage("invalid Email"),
     body("username")
     .trim()
     .notEmpty()
     .withMessage("Username is required!! ")

]
};
