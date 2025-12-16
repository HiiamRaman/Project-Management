import { Router } from "express";
import {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  ResetPasswordReqValidator,
  forgotPasswordReqValidator,
} from "../validator/index.js";
import {
  ResetPasswordReq,
  ChangeCurrentpassword,
  resendEmailverification,
  refreshAccessToken,
  getCurrentUser,
  registerUser,
  verifyEmail,
  forgotPasswordReq,
} from "../controllers/auth.controller.js";
import { validate } from "../middleware/validator.middleware.js";
import { login } from "../controllers/auth.controller.js";
import { logoutUser } from "../controllers/auth.controller.js";
import { verifyJWT } from "../middleware/auth.middleware.js";

const router = Router();

//unsecure routes

router.route("/register").post(userRegisterValidator(), validate, registerUser); //userRegisterValidator will collect error and validate will catch
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verifyEmail/:verificationToken").get(verifyEmail);
router.route("/refreshToken").post(refreshAccessToken);
router
  .route("/forgot-password")
  .post(forgotPasswordReqValidator(), validate, forgotPasswordReq);
router
  .route("/reset-password/:resetToken")
  .post(ResetPasswordReqValidator(), validate, ResetPasswordReq);
//secure routes
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/currentUser").post(verifyJWT, getCurrentUser);
router
  .route("/changePassword")
  .post(
    verifyJWT,
    userChangeCurrentPasswordValidator(),
    validate,
    ChangeCurrentpassword
  );
router
  .route("/resendEmailVerification")
  .post(verifyJWT, resendEmailverification);
export default router;
