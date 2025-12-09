import { Router } from "express";
import { userRegisterValidator } from "../validator/index.js";
import { registerUser } from "../controllers/auth.controller.js";
import { validate } from "../middleware/validator.middleware.js";
const router = Router();

router.route("/register").post(userRegisterValidator(), validate, registerUser); //userRegisterValidator will collect error and validate will catch

export default router;
