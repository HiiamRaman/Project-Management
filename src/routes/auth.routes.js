import { Router } from "express";
import { userRegisterValidator } from "../validator/index.js";
import { registerUser } from "../controllers/auth.controller.js";
import { validate } from "../middleware/validator.middleware.js";
import { login } from "../controllers/auth.controller.js";
const router = Router();

router.route("/register").post(userRegisterValidator(), validate, registerUser); //userRegisterValidator will collect error and validate will catch
router.route("/login").post(login); 

export default router