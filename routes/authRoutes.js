import express from "express"
import { loginController, otpResetPasswordController, profileController, protectedController, registerController, resetPasswordController, verifyEmailController } from "../controllers/authController.js";
import { isAuthenticated, isAuthorized } from "../middlewares/auth.js";
import Roles from "../constants/index.js"
import registerValidator from "../validators/register-validator.js";
import loginValidator from "../validators/login-validator.js";
import profileUpdateValidator from "../validators/profileUpdate-validator.js";
import resetPasswordValidator from "../validators/resetPassword-validator.js";
import { uploadAvatar } from "../middlewares/updateAvatar.js";
import { updateProfileController } from "../controllers/updateProfile.js";

const  router= express.Router();

// complete route...api/auth/register....
router.post("/register",registerValidator, registerController);

router.post("/verifyEmail", verifyEmailController)

router.post("/login",loginValidator, loginController)
// complete route  ...api/auth/profile/ghgj4644gjjgj
router.get("/profile/:id",isAuthenticated, profileController)


router.put("/updateProfile",uploadAvatar, profileUpdateValidator, isAuthenticated, updateProfileController)

router.post("/otpResetPassword",otpResetPasswordController)

router.post("/resetPassword",resetPasswordValidator, resetPasswordController)

router.get(
    "/protected",
    isAuthenticated,
    isAuthorized([Roles.ADMIN,Roles.SUPER_ADMIN]),
    protectedController
)


export default router