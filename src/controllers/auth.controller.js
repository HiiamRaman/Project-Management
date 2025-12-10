import { User } from "../models/user.models.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asynHandler.js";
import { sendEmail, emailVerificationMailgenContent } from "../utils/mail.js";
import { generateAccessAndRefreshToken } from "../service/generateTokens.service.js";
import mongoose from "mongoose";

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

  const  userId  = req.user._id;
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
