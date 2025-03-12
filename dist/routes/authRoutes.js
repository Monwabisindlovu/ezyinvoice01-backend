"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const google_auth_library_1 = require("google-auth-library");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const express_validator_1 = require("express-validator");
const passport_1 = __importDefault(require("passport"));
const User_1 = __importDefault(require("../models/User"));
const authService_1 = __importDefault(require("../services/authService"));
const sendEmail_1 = __importDefault(require("../utils/sendEmail"));
const encrypt_1 = __importDefault(require("../utils/encrypt"));
const smsService_1 = require("../utils/smsService");
const authMiddleware_1 = require("../middleware/authMiddleware"); // Your JWT auth middleware
const router = (0, express_1.Router)();
const googleClient = new google_auth_library_1.OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// Utility function to validate and send errors
const handleValidationErrors = (req, res) => {
    const errors = (0, express_validator_1.validationResult)(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return true; // Return true if there are validation errors
    }
    return false; // Return false if there are no errors
};
// Google OAuth Callback Route
router.get("/google/redirect", passport_1.default.authenticate("google"), (req, res) => {
    if (!req.user) {
        res.status(400).json({ message: "Authentication failed, no user found" });
        return;
    }
    // Generate the JWT token from the authenticated user document
    const jwtToken = req.user.generateJwtToken();
    res.status(200).json({ token: jwtToken, user: req.user });
});
// Register Route (Email/Password)
router.post("/register", [
    (0, express_validator_1.body)("email").isEmail().withMessage("Please enter a valid email"),
    (0, express_validator_1.body)("password").isLength({ min: 7, max: 12 }).withMessage("Password must be between 7 to 12 characters"),
    (0, express_validator_1.body)("confirmPassword").custom((value, { req }) => value === req.body.password).withMessage("Passwords must match"),
], (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    if (handleValidationErrors(req, res))
        return; // Handle validation errors
    const { email, phone, password } = req.body;
    try {
        const userExists = yield User_1.default.findOne({ email });
        if (userExists) {
            res.status(400).json({ message: "User already exists" });
            return; // Early return after response
        }
        const hashedPassword = yield bcryptjs_1.default.hash(password, 12);
        const newUser = new User_1.default({
            email,
            phone,
            password: hashedPassword,
        });
        yield newUser.save();
        res.status(201).json({ message: "User registered successfully" });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
}));
// Login Route (Email/Password or Google OAuth token)
router.post("/login", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { emailOrPhone, password, googleToken } = req.body;
        let user;
        if (googleToken) {
            const ticket = yield googleClient.verifyIdToken({
                idToken: googleToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });
            const payload = ticket.getPayload();
            if (!payload) {
                res.status(400).json({ message: "Invalid Google token" });
                return; // Early return after response
            }
            user = yield User_1.default.findOne({ email: payload.email });
        }
        else {
            user = yield User_1.default.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });
            if (!user || !(yield bcryptjs_1.default.compare(password, user.password || ''))) {
                res.status(400).json({ message: "Invalid credentials" });
                return; // Early return after response
            }
        }
        if (!user) {
            res.status(400).json({ message: "User not found" });
            return; // Early return after response
        }
        const token = user.generateJwtToken();
        res.json({ token }); // Respond with token
    }
    catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
}));
// Refresh Token Route
router.post("/refresh", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { refreshToken } = req.body;
    try {
        const userData = authService_1.default.verifyRefreshToken(refreshToken);
        const newAccessToken = authService_1.default.createJwtToken(userData.userId);
        res.status(200).json({ newAccessToken });
    }
    catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
}));
// Forgot Password Route
router.post("/forgot-password", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { emailOrPhone } = req.body;
    try {
        const user = yield User_1.default.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });
        if (!user) {
            res.status(400).json({ message: "User not found" });
            return; // Early return after response
        }
        const resetToken = encrypt_1.default.generateRandomToken();
        // Ensure email or phone is defined
        let message;
        if (user.email === emailOrPhone) {
            yield (0, sendEmail_1.default)(user.email, resetToken); // Always assert that user.email is string here
            message = "Password reset email sent";
        }
        else if (user.phone === emailOrPhone) {
            if (!user.phone) {
                res.status(400).json({ message: "Phone number is required" });
                return; // Early return after response
            }
            else {
                yield (0, smsService_1.sendResetSMS)(user.phone, resetToken);
                message = "Password reset SMS sent";
            }
        }
        else {
            res.status(400).json({ message: "User verification failed." });
            return;
        }
        res.json({ message });
    }
    catch (error) {
        console.error("Error during password reset request:", error);
        res.status(500).json({ message: "Server error" });
    }
}));
// Reset Password Route
router.post("/reset-password", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { emailOrPhone, verificationCode, newPassword } = req.body;
    try {
        const decoded = jsonwebtoken_1.default.verify(verificationCode, process.env.JWT_SECRET);
        const user = yield User_1.default.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });
        if (!user) {
            res.status(400).json({ message: "Invalid token or user not found" });
            return; // Early return after response
        }
        user.password = yield encrypt_1.default.hashPassword(newPassword);
        yield user.save();
        res.json({ message: "Password reset successfully" });
    }
    catch (error) {
        console.error("Reset Password Server Error:", error);
        res.status(500).json({ message: "Server error", error: error instanceof Error ? error.message : String(error) });
    }
}));
// Protected profile route
router.get("/profile", authMiddleware_1.authenticateJWT, (req, res) => {
    res.status(200).json({ user: req.user });
});
// Logout Route
router.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ message: 'Error logging out' });
        }
        res.redirect("/"); // Redirect to the home page after logout
    });
});
// Login Page Route
router.get("/login", (req, res) => {
    if (req.user) {
        return res.redirect("/profile");
    }
    res.render("login"); // Render the login page if not authenticated
});
exports.default = router;
