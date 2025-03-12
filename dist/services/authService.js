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
exports.verifyRefreshToken = exports.loginUser = exports.findUserByEmail = exports.registerUser = exports.verifyGoogleToken = exports.createRefreshToken = exports.createJwtToken = exports.comparePassword = exports.hashPassword = void 0;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const User_1 = __importDefault(require("../models/User"));
const google_auth_library_1 = require("google-auth-library");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const client = new google_auth_library_1.OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// Function to hash the password
const hashPassword = (password) => __awaiter(void 0, void 0, void 0, function* () {
    const salt = yield bcryptjs_1.default.genSalt(10);
    return bcryptjs_1.default.hash(password, salt);
});
exports.hashPassword = hashPassword;
// Function to compare passwords
const comparePassword = (password, hashedPassword) => __awaiter(void 0, void 0, void 0, function* () {
    return bcryptjs_1.default.compare(password, hashedPassword);
});
exports.comparePassword = comparePassword;
// Function to create JWT token
const createJwtToken = (userId) => {
    return jsonwebtoken_1.default.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};
exports.createJwtToken = createJwtToken;
// Function to create JWT refresh token
const createRefreshToken = (userId) => {
    return jsonwebtoken_1.default.sign({ userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
};
exports.createRefreshToken = createRefreshToken;
// Function to verify Google OAuth token
const verifyGoogleToken = (token) => __awaiter(void 0, void 0, void 0, function* () {
    const ticket = yield client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID, // Specify the client ID of your app
    });
    return ticket.getPayload();
});
exports.verifyGoogleToken = verifyGoogleToken;
// Function to create a new user in the database
const registerUser = (email, password) => __awaiter(void 0, void 0, void 0, function* () {
    const hashedPassword = password ? yield (0, exports.hashPassword)(password) : undefined;
    const user = new User_1.default({ email, password: hashedPassword });
    return user.save();
});
exports.registerUser = registerUser;
// Function to find a user by email
const findUserByEmail = (email) => __awaiter(void 0, void 0, void 0, function* () {
    return User_1.default.findOne({ email });
});
exports.findUserByEmail = findUserByEmail;
// Function to handle user login
const loginUser = (email, password, googleToken) => __awaiter(void 0, void 0, void 0, function* () {
    let user = yield (0, exports.findUserByEmail)(email);
    if (googleToken) {
        const googlePayload = yield (0, exports.verifyGoogleToken)(googleToken);
        if (!user) {
            user = yield (0, exports.registerUser)(email); // Register new user if not found
        }
    }
    else {
        if (!user) {
            throw new Error('User not found');
        }
        const isMatch = yield (0, exports.comparePassword)(password, user.password);
        if (!isMatch) {
            throw new Error('Invalid credentials');
        }
    }
    // Explicitly cast _id to ObjectId to avoid type error
    const userId = user._id;
    // Create tokens
    const accessToken = (0, exports.createJwtToken)(userId.toString());
    const refreshToken = (0, exports.createRefreshToken)(userId.toString());
    return { accessToken, refreshToken, user };
});
exports.loginUser = loginUser;
// Function to verify refresh token
const verifyRefreshToken = (token) => {
    try {
        return jsonwebtoken_1.default.verify(token, process.env.JWT_REFRESH_SECRET);
    }
    catch (error) {
        throw new Error('Invalid or expired refresh token');
    }
};
exports.verifyRefreshToken = verifyRefreshToken;
const authService = {
    hashPassword: exports.hashPassword,
    comparePassword: exports.comparePassword,
    createJwtToken: exports.createJwtToken,
    createRefreshToken: exports.createRefreshToken,
    verifyGoogleToken: exports.verifyGoogleToken,
    registerUser: exports.registerUser,
    findUserByEmail: exports.findUserByEmail,
    loginUser: exports.loginUser,
    verifyRefreshToken: exports.verifyRefreshToken,
};
exports.default = authService;
