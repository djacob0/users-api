const express = require("express");
const UserController = require("../controllers/UserController");
const sessionMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

router.get("/users", sessionMiddleware, UserController.getAllUsers);
router.get("/users/:id", sessionMiddleware, UserController.getUserById);
router.post("/register", UserController.registerUser);
router.post("/login", UserController.loginUser);
router.put("/users/:id", sessionMiddleware, UserController.updateUser);
router.delete("/users/:id", sessionMiddleware, UserController.deleteUser);

module.exports = router;
