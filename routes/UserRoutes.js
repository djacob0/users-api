const express = require("express");
const UserController = require("../controllers/UserController");
const router = express.Router();

router.post("/signup", UserController.signup);
router.post("/login", UserController.login);
router.post("/logout", UserController.logout);
router.get("/profile", UserController.profile);
router.get("/users", UserController.getAllUsers);
router.post("/users", UserController.createUser);
router.put("/users/:id", UserController.updateUser); 
router.delete("/users/:id", UserController.deleteUser);
router.post("/verify-login-otp", UserController.verifyLoginOtp);
router.post("/verify-signup-otp", UserController.verifySignupOtp);
router.post('/forgot-password', UserController.requestPasswordReset);
router.post('/reset-password', UserController.verifyPasswordReset);
router.post('/resend-otp', UserController.resendOtp);

module.exports = router;