import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asynHandler.js";
export const healthCheck = asyncHandler(async function (req, res) {
  return res
    .status(200)
    .json(new ApiResponse(200, null, "Server is Runing !!!"));
});
