import { Router } from "express";
import { userRegisterValidator,userLoginValidator } from "../validator/index.js";
import { registerUser } from "../controllers/auth.controller.js";
import { validate } from "../middleware/validator.middleware.js";
import { login } from "../controllers/auth.controller.js";
import { logoutUser } from "../controllers/auth.controller.js";
import { verifyJWT } from "../middleware/auth.middleware.js";

const router = Router();

router.route("/register").post(userRegisterValidator(), validate, registerUser); //userRegisterValidator will collect error and validate will catch
router.route("/login").post(userLoginValidator(),validate,login); 
router.route("/logout").post(verifyJWT,logoutUser); 

export default router