import { User } from "../models/user.models.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asynHandler.js";
import { sendEmail, emailVerificationMailgenContent } from "../utils/mail.js";
import { generateAccessAndRefreshToken } from "../service/generateTokens.service.js";

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
export const registerUser = asyncHandler(async (req, res) => {
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
  const { accessToken, refreshToken } = user.generateAccessAndRefreshToken(
    user._id
  );

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
});
