"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
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
const validationMiddleware_1 = require("../middleware/validationMiddleware");
const encryptUtils = __importStar(require("../utils/encrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const User_1 = __importDefault(require("../models/User"));
const google_auth_library_1 = require("google-auth-library");
const sendEmail_1 = require("../utils/sendEmail");
const smsService_1 = require("../utils/smsService");
const client = new google_auth_library_1.OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// Function to validate password with specified rules
const validatePassword = (password) => {
    const passwordPattern = /^(?=.*[0-9])(?=.*[!@#$%^&*])[A-Za-z0-9!@#$%^&*]{7,12}$/;
    return passwordPattern.test(password);
};
// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Unauthorized: No token provided" });
        }
        const token = authHeader.split(" ")[1];
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        const user = yield User_1.default.findById(decoded.id).exec();
        if (!user) {
            return res.status(401).json({ message: "Invalid token." });
        }
        req.user = user;
        next();
    }
    catch (error) {
        console.error('JWT Authentication Error:', error);
        res.status(401).json({ message: "Invalid or expired token." });
    }
});
const AuthController = {
    register: [
        ...validationMiddleware_1.validateRegister,
        validationMiddleware_1.handleValidationErrors,
        (req, res) => __awaiter(void 0, void 0, void 0, function* () {
            try {
                console.log('Incoming Request Body:', req.body);
                const { email, phone, password } = req.body;
                if (!email && !phone) {
                    console.log('Validation Error: Email or phone is required');
                    return res.status(400).json({ message: 'Email or phone is required' });
                }
                console.log('Checking for existing user...');
                const existingUser = yield User_1.default.findOne({ $or: [{ email }, { phone }] });
                if (existingUser) {
                    console.log('Validation Error: User already exists');
                    return res.status(400).json({ message: 'User already exists' });
                }
                console.log('Hashing password...');
                const hashedPassword = yield encryptUtils.hashPassword(password);
                console.log('Password hashed successfully');
                console.log('Creating new user...');
                const newUser = new User_1.default({
                    email,
                    phone,
                    password: hashedPassword,
                });
                yield newUser.save();
                console.log('New user created and saved successfully');
                res.status(201).json({ message: 'User registered successfully' });
            }
            catch (error) {
                if (error instanceof Error) {
                    if (error.message.includes('E11000')) {
                        console.log('Duplicate key error:', error.message);
                        return res.status(400).json({ message: 'User with this email or phone already exists' });
                    }
                    console.error('Registration Server Error:', {
                        message: error.message,
                        stack: error.stack,
                    });
                    res.status(500).json({ message: 'Server error', error: error.message });
                }
                else {
                    console.error('Unexpected error:', error);
                    res.status(500).json({ message: 'Server error', error });
                }
            }
        })
    ],
    login: (req, res) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            console.log('Login Request Body:', req.body);
            const { emailOrPhone, password } = req.body;
            if (!emailOrPhone) {
                return res.status(400).json({ message: 'Email or phone is required' });
            }
            let phone = emailOrPhone;
            if (phone && !phone.startsWith('+')) {
                phone = `+27${phone.substring(1)}`;
            }
            const user = yield User_1.default.findOne({
                $or: [
                    { email: emailOrPhone },
                    { phone },
                ],
            });
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            console.log('User found:', user);
            const isPasswordValid = yield encryptUtils.comparePassword(password, user.password);
            if (!isPasswordValid) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            const token = user.generateJwtToken();
            res.status(200).json({ message: 'Login successful', token });
        }
        catch (error) {
            if (error instanceof Error) {
                console.error('Login Server Error:', {
                    message: error.message,
                    stack: error.stack,
                });
                res.status(500).json({ message: 'Server error', error: error.message });
            }
            else {
                console.error('Unexpected error:', error);
                res.status(500).json({ message: 'Server error', error });
            }
        }
    }),
    googleAuth: (req, res) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const { token } = req.body;
            if (!token) {
                return res.status(400).json({ message: 'Token is required.' });
            }
            const ticket = yield client.verifyIdToken({
                idToken: token,
                audience: process.env.GOOGLE_CLIENT_ID,
            });
            const googlePayload = ticket.getPayload();
            if (!googlePayload) {
                return res.status(400).json({ message: 'Invalid Google token' });
            }
            const { email, sub: googleId, name, picture } = googlePayload;
            let user = yield User_1.default.findOne({ email }).exec();
            if (!user) {
                user = new User_1.default({
                    email,
                    googleId,
                    name,
                    avatar: picture,
                    password: 'google-oauth', // Dummy password; consider handling this appropriately
                });
                yield user.save();
                console.log('🔹 New Google user created:', user);
            }
            else {
                if (!(user instanceof User_1.default)) {
                    user = yield User_1.default.findById(user._id).exec();
                }
                console.log('🔹 Existing user found:', user);
            }
            // Ensure user is not null before generating JWT
            if (!user) {
                return res.status(404).json({ message: 'User not found after checking' });
            }
            const jwtToken = user.generateJwtToken();
            console.log('🔹 JWT Token generated:', jwtToken);
            res.status(200).json({ token: jwtToken, user });
        }
        catch (error) {
            console.error('Google Auth Error:', error);
            res.status(500).json({
                message: 'Server error',
                error: error instanceof Error ? error.message : error,
            });
        }
    }),
    forgotPassword: (req, res) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const { emailOrPhone } = req.body;
            if (!emailOrPhone) {
                return res.status(400).json({ message: 'Email or phone is required' });
            }
            const user = yield User_1.default.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });
            if (!user) {
                return res.status(400).json({ message: 'User not found' });
            }
            const resetToken = encryptUtils.generateRandomToken();
            if (user.email === emailOrPhone) {
                yield (0, sendEmail_1.sendPasswordResetEmail)(user.email, resetToken);
                res.json({ message: 'Password reset email sent' });
            }
            else if (user.phone === emailOrPhone) {
                // Ensure user.phone is a defined string before sending SMS
                if (!user.phone) {
                    return res.status(400).json({ message: 'User phone number is missing' });
                }
                yield (0, smsService_1.sendResetSMS)(user.phone, resetToken);
                res.json({ message: 'Password reset SMS sent' });
            }
        }
        catch (error) {
            if (error instanceof Error) {
                console.error('Forgot Password Server Error:', {
                    message: error.message,
                    stack: error.stack,
                });
                res.status(500).json({ message: 'Server error', error: error.message });
            }
            else {
                console.error('Unexpected error:', error);
                res.status(500).json({ message: 'Server error', error });
            }
        }
    }),
    resetPassword: (req, res) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const { token, newPassword } = req.body;
            if (!validatePassword(newPassword)) {
                return res.status(400).json({
                    message: 'Password must be 7-12 characters long, contain at least one number and one special character',
                });
            }
            if (!process.env.JWT_SECRET) {
                return res.status(500).json({ message: 'Server error: Missing JWT secret' });
            }
            const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
            const user = yield User_1.default.findById(decoded.id);
            if (!user)
                return res.status(400).json({ message: 'Invalid token' });
            user.password = yield encryptUtils.hashPassword(newPassword);
            yield user.save();
            res.json({ message: 'Password reset successfully' });
        }
        catch (error) {
            if (error instanceof Error) {
                console.error('Reset Password Server Error:', {
                    message: error.message,
                    stack: error.stack,
                });
                res.status(500).json({ message: 'Server error', error: error.message });
            }
            else {
                console.error('Unexpected error:', error);
                res.status(500).json({ message: 'Server error', error });
            }
        }
    })
};
exports.default = AuthController;
