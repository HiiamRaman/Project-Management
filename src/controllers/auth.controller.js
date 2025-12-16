import { User } from "../models/user.models.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asynHandler.js";
import { sendEmail, emailVerificationMailgenContent } from "../utils/mail.js";
import { generateAccessAndRefreshToken } from "../service/generateTokens.service.js";
import mongoose from "mongoose";
import  dotenv  from "dotenv";
dotenv.config()
//Register User
/**
 *  Mental Workflow:
 * -------------------------------------------------------
 * 1️⃣ Extract input fields from request body:
 *     email, username, password, fullname (optional), role (optional)
 *
 * 2️⃣ Validate required fields:
 *     - email, username, password must exist and not be empty
 *
 * 3️⃣ Check for duplicates:
 *     - Search DB for existing user with same email or username
 *     - If found → throw error
 *
 * 4️⃣ Create user in DB:
 *     - Save email, username, password (hashed automatically by model)
 *     - Save fullname, role
 *     - Set isEmailVerified: false
 *
 * 5️⃣ Generate temporary verification token:
 *     - unhashedToken = crypto.randomBytes()
 *     - hashedToken = SHA256(unhashedToken)
 *     - tokenExpiry = Date.now() + 20 mins
 *
 * 6️⃣ Save token in DB:
 *     - emailVerificationToken = hashedToken
 *     - emailVerificationExpiry = tokenExpiry
 *
 * 7️⃣ Send verification email:
 *     - Generate verification link: /verify-email/:unhashedToken
 *     - Send email using Nodemailer + Mailgen
 *
 * 8️⃣ Return safe user response:
 *     - Exclude password, refreshToken, emailVerificationToken, emailVerificationExpiry
 *     - Return 201 Created + success message
 *
 * 9️⃣ Next step for user:
 *     - User clicks verification link
 *     - Backend validates token → sets isEmailVerified = true
 * -------------------------------------------------------
 */
export const registerUser = async (req, res) => {
  console.log("register process begin:");
  const { email, password, username, role, fullname } = req.body;

  //  Validate required fields
  if (!email || !password || !username || !role || !fullname) {
    throw new ApiError(400, "All fields are required!!!!");
  }

  // check for the existing users
  const existinguser = await User.findOne({
    $or: [{ email }, { username }],
  });
  if (existinguser) {
    throw new ApiError(400, "User with email or username already exists!!");
  }
  //  Create new user in DB
  const user = await User.create({
    email,
    username,
    fullname,
    role,
    password,
    isEmailVerified: false,
  });

  //generating tokens here are not necessary because we dont send them to frontend while register,
  //Return tokens immediately after registration This is common if you want the user to be logged in immediately after signup.
  //generate refresh token and access token

  const { accessToken, refreshToken } = generateAccessAndRefreshToken(user._id);

  //  Generate temporary email verification token that we defined in user.model

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;
  //  Save token to DB
  await user.save({ validateBeforeSave: false });

  // -------------------------------------------------------
  //  Send verification email
  const verificationLink = `${req.protocol}://${req.get("host")}/api/v1/user/verify-email/${unhashedToken}`;
  await sendEmail({
    email: user?.email,
    subject: "please Verify Your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      verificationLink
    ),
  });

  // -------------------------------------------------------
  //  Return safe user info
  // Exclude sensitive fields such as password, refreshToken, verification token & expiry
  const safeUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );
  if (!safeUser) {
    throw new ApiError(500, "Something went wrong while registering user");
  }

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: safeUser },
        "User registered successfully!! and verification email has sent to your email "
      )
    );
};

//login controllers

export const login = asyncHandler(async (req, res) => {
  /*
       MENTAL FLOW:
      1. Extract email & password.
      2. Validate both.
      3. Check if user exists.
      4. Compare password using user.isPasswordCorrect().
      5. Generate access & refresh tokens.
      6. Store refresh token in database.
      7. Create secure cookie options.
      8. Set access & refresh tokens as cookies.
      9. Send safe user info + message.
  */
  const { email, password } = req.body;
  if (!email || !password) {
    throw new ApiError(400, "email and password are reqired !!");
  }

  // Step 2: find the user by email

  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(400, "invalid email!!");
  }

  // Compare password using user.isPasswordCorrect().

  const validpassword = await user.isPasswordCorrect(password);

  if (!validpassword) {
    throw new ApiError(400, "Invalid password");
  }

  //Generate access & refresh tokens.

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  //Save refresh token in DB

  user.refreshToken = refreshToken;

  await user.save({ validateBeforeSave: false });

  //  Cookie options

  const Options = {
    httpOnly: true,
    secure: true,
  };

  // 8 — Set cookies

  res.cookie("accessToken", accessToken, Options);
  res.cookie("refreshToken", refreshToken, Options);
  const safeUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  /* this can be done in another way also like

safeUser = {
_id : user._id,
name:user.name,
email:user.email

}  */

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: safeUser, refreshToken, accessToken },
        "user loggedin successfully!!"
      )
    );
});

export const logoutUser = asyncHandler(async (req, res) => {
  const { accessToken, refreshToken } = req.cookies;
  const user = await User.findByIdAndUpdate(
    req.user._id,
    { $unset: { refreshToken } },
    { new: true }
  );
  if (!user) {
    throw new ApiError(404, "user not found");
  }
  const options = {
    httpOnly: true,
    secure: true,
  };

  res.clearCookie("accessToken", accessToken, options);
  res.clearCookie("refreshToken", refreshToken, options);

  return res
    .status(200)
    .json(new ApiResponse(200, null, "Userlogged out successfullty!!"));
});

export const getCurrentUser = asyncHandler(async (req, res) => {
  /*
      MENTAL FLOW:
      1. Extract userId from req.user (set by verifyJWT middleware)
      2. Validate userId
      3. Fetch user from DB without sensitive fields
      4. If not found, throw error
      5. Return structured response
  */
  //1. Extract userId from req.user (set by verifyJWT middleware

  const userId = req.user._id;
  if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
    throw new ApiError(400, "invalid userId");
  }

  //Fetch user from DB
  const user = await User.findById(userId).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -__v"
  );

  if (!user) {
    throw new ApiError(404, "user not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, user, "user fetched successfully!!"));
});

export const verifyEmail = asyncHandler(async (req, res) => {
  /*
    MENTAL FLOW:
    1. Extract token from params
    2. Validate token
    3. Find user with token and unexpired
    4. If not found, throw error
    5. Set isVerified true, remove token fields
    6. Save user
    7. Return success response
*/
  //Extract
  const { verificationToken } = req.params;

  //2. Validate token
  if (!verificationToken || typeof verificationToken !== "string") {
    throw new ApiError(400, "Invalid or missing verificationToken");
  }

  // 2.1 we hashed the verification  token while storing in db so lets hash the verification token to match with db token

  const hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  //Find user with matching token and valid expiry

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() }, // $gt: Date.now() ensures we only find tokens that are still valid (expiry time is in the future)
  });

  if (!user) {
    throw new ApiError(404, "Invalid or expired email verification token");
  }

  //lets mark email isverified true

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;
  await user.save();

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { isEmailVerified: true },
        "Email verified successfully!!!"
      )
    );
});

export const resendEmailverification = asyncHandler(async (req, res) => {
  /*
      MENTAL FLOW:
      1. Extract email from request body
      2. Validate that email is provided
      3. Find the user by email
      4. If user does not exist → throw error
      5. If user is already verified → throw error


      after this we did same process while registering user
      6. Generate a new email verification token (random bytes)
      7. Hash the token with SHA256 before storing in DB
      8. Set token expiry time (e.g., 1 hour from now)
      9. Save the user document
      10. Send verification email with plain token in URL
      11. Return a success response with minimal user info
  */

  const { email } = req.body;

  if (!email || typeof email !== "string") {
    throw new ApiError(400, "Invalid Email!!");
  }

  // Find the user by email

  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(400, "User not found!!!");
  }
  // If user is already verified → throw error

  if (user.isEmailVerified) {
    throw new ApiError(400, "user email is already verified!!");
  }

  // after this we did same process while registering user

  //  Generate temporary email verification token

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;
  //  Save token to DB
  await user.save({ validateBeforeSave: false });

  // -------------------------------------------------------
  //  Send verification email
  const verificationLink = `${req.protocol}://${req.get("host")}/api/v1/user/verify-email/${unhashedToken}`;
  await sendEmail({
    email: user?.email,
    subject: "please Verify Your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      verificationLink
    ),
  });

  // -------------------------------------------------------
  //  Return safe user info
  // Exclude sensitive fields such as password, refreshToken, verification token & expiry

  const safeUser = {
    _id: user._id,
    email: user.email,
    username: user.username, // optional, if you want
    isEmailVerified: user.isEmailVerified, // optional
  };

  return res
    .status(200)
    .json(
      new ApiResponse(200, safeUser, "Verification email sent successfully!")
    );
});

export const refreshAccessToken = asyncHandler(async (req, res) => {
  /*
      MENTAL FLOW:
      1. Extract refresh token from cookies
      2. Validate token exists
      3. Verify token signature and decode payload //in simply it says to decode and compare the extracted refresh token with 
      4. Fetch user from DB using decoded id
      5. Ensure stored refresh token matches the token received
      6. Generate new access token
      7. Return access token in response
  */

  //  Extract refresh token from cookies

  console.log("COOKIE TOKEN:", req.cookies?.refreshToken);
console.log("BODY TOKEN:", req.body?.refreshToken);

  const incomingrefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingrefreshToken) {
    throw new ApiError(400, "Token not found ");
  }

  // Verify token signature
  let decodedToken;
  try {
    console.log("REFRESH SECRET IN VERIFY:", process.env.REFRESH_TOKEN_SECRET);
    console.log("Incoming refresh token:", incomingrefreshToken);
console.log("All cookies:", req.cookies);
console.log("Request body:", req.body);

    decodedToken = jwt.verify(
      incomingrefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
  } catch (error) {
    throw new ApiError(400, "invalid Token or Expired token");
  }

  // Fetch user from DB
  const user = await User.findById(decodedToken._id);

  if (!user) {
    throw new ApiError(404, "user not found!!");
  }

  // Ensure stored refresh token matches the token received

  if (user.refreshToken !== incomingrefreshToken) {
    throw new ApiError(400, "Refresh token does not match");
  }

  //  Generate new access token

  const { accessToken, refreshToken } = generateAccessAndRefreshToken(user._id);


  console.log("Incoming refresh token:", incomingrefreshToken);
console.log("User stored refresh token:", user.refreshToken);


  user.refreshToken = refreshToken;

  await user.save({ validateBeforeSave: false });
  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV==="production",
     sameSite: "lax",
  };
  res.cookie("refreshToken", refreshToken, options);
  res.cookie("accessToken", accessToken, options);

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { refreshToken, accessToken },
        "Refreshtoken refreshed Access token successfully!!"
      )
    );
});

export const forgotPasswordReq = asyncHandler(async (req, res) => {
  /*
      MENTAL FLOW:
      1. Extract email from request
      2. Validate email
      3. Find user by email
      4. Generate a secure password reset token
      5. Hash token and store it in DB with expiry time
      6. Save the user (without validation)
      7. Generate reset URL to send to email
      8. Email the reset link to the user
      9. Respond with success message
  */
  // Extract email from request

  const { email } = req.body;
  if (!email || typeof email !== "string") {
    throw new ApiError(400, "email not found");
  }

  // Find user by email

  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "user not found!!");
  }

  // Generate a secure password reset token (basically measn the temporary token)

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  // Generate reset URL to send to email or //  Send passwordResetUrl email like we did on register user
  const passwordResetUrl = `${req.protocol}://${req.get("host")}/api/v1/users/reset-password/${unhashedToken}`;
  await sendEmail({
    email: user?.email,
    subject: "You requested a password reset for your account",
    mailgenContent: forgotPasswordMailgenContent(
      user.username || user.fullname,
      passwordResetUrl
    ),
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "If the email exists, a reset link has been sent"
      )
    );
});
export const ResetPasswordReq = asyncHandler(async (req, res) => {
  /*
      MENTAL FLOW:
      1. Extract reset token from URL params
      2. Extract new password from request body
      3. Validate inputs
      4. Hash the incoming token (because DB stores hashed token)
      5. Find user with matching token and non-expired expiry
      6. If user not found → token invalid or expired
      7. Update user password
      8. Clear reset token and expiry (single-use token)
      9. Save user
      10. Respond with success message
  */

  // Extract reset token from URL params

  const { resetToken } = req.params;

  // Extract new password from request body

  const { newpassword, confirmPassword } = req.body;

  if (!resetToken) {
    throw new ApiError(400, "Reset token is missing");
  }

  if (!newpassword || typeof newpassword !== "string") {
    throw new ApiError(400, "Invalid newpassword!!!");
  }

  if (!confirmPassword || newpassword !== confirmPassword) {
    throw new ApiError(400, "Password doesnot match!!!");
  }

  //  Hash the incoming token (because DB stores hashed token)

  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Find user with matching token and non-expired expiry

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });
  if (!user) {
    throw new ApiError(400, "Token is invalid or has expired");
  }

  // Update user password
  user.password = newpassword;

  // Clear reset token and expiry (single-use token)
  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;
  await user.save();

  // Respond with success message

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Password reset successful. You can now log in with your new password."
      )
    );
});

export const ChangeCurrentpassword = asyncHandler(async (req, res) => {
  /*
      MENTAL FLOW:
      1. Extract userId from req.user (set by verifyJWT middleware)
      2. Extract currentPassword, newPassword, confirmPassword from body
      3. Validate inputs
      4. Fetch user from DB
      5. Verify currentPassword matches stored password
     
      7. Validate newPassword === confirmPassword
      8. Update password
      9. Save user with model validations
      10. Respond with success message
  */

  const userId = req.user._id;
  const { currentPassword, newPassword, confirmPassword } = req.body;
  if (!currentPassword || !newPassword || !confirmPassword) {
    throw new ApiError(400, "All Fields are required!!!");
  }

  const user = await User.findById(userId);

  if (!user) {
    throw new ApiError(404, "user not found !!!");
  }

  const isMatch = await user.isPasswordCorrect(currentPassword);

  if (!isMatch) {
    throw new ApiError(400, "Invalid currentPassword!!!");
  }

  if (newPassword !== confirmPassword) {
    throw new ApiError(400, "passwords donot match!!");
  }

  user.password = newPassword;
  await user.save();
  res
    .status(200)
    .json(new ApiResponse(200, {}, "password changed Successfully!! "));
});
