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
exports.authorizeRoles = exports.authenticateJWT = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const User_1 = __importDefault(require("../models/User"));
/**
 * Middleware to authenticate JWT
 */
const authenticateJWT = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const token = (_a = req.headers.authorization) === null || _a === void 0 ? void 0 : _a.split(' ')[1]; // Extract token
    if (!token) {
        res.status(401).json({ message: 'Unauthorized: No token provided' });
        return; // ✅ Simply return instead of casting to void
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET); // Verify token and extract userId
        const user = yield User_1.default.findById(decoded.userId).select('-password'); // Select user excluding password
        if (!user) {
            res.status(401).json({ message: 'Unauthorized: User not found' });
            return; // ✅ Just return instead of casting to void
        }
        req.user = user; // Attach user to request object
        next(); // Move to the next middleware
    }
    catch (error) {
        res.status(403).json({ message: 'Forbidden: Invalid token' });
        return; // ✅ Simply return instead of casting to void
    }
});
exports.authenticateJWT = authenticateJWT;
/**
 * Middleware to authorize user roles
 */
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
            return; // ✅ Simply return instead of casting to void
        }
        next(); // Continue if authorized
    };
};
exports.authorizeRoles = authorizeRoles;
exports.default = { authenticateJWT: exports.authenticateJWT, authorizeRoles: exports.authorizeRoles };
