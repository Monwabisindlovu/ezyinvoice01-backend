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
exports.decryptData = exports.encryptData = exports.generateRandomToken = exports.comparePassword = exports.hashPassword = void 0;
const bcryptjs_1 = __importDefault(require("bcryptjs")); // Only use bcryptjs, not bcrypt
const crypto_1 = __importDefault(require("crypto"));
// Hash password before storing it in the database
const hashPassword = (password) => __awaiter(void 0, void 0, void 0, function* () {
    const salt = yield bcryptjs_1.default.genSalt(12);
    return yield bcryptjs_1.default.hash(password, salt);
});
exports.hashPassword = hashPassword;
// Compare entered password with stored hashed password
const comparePassword = (password, hashedPassword) => __awaiter(void 0, void 0, void 0, function* () {
    return bcryptjs_1.default.compare(password, hashedPassword); // Use bcrypt's compare function directly
});
exports.comparePassword = comparePassword;
// Function to generate a random token (for encryption, reset tokens, etc.)
const generateRandomToken = (length = 32) => {
    return crypto_1.default.randomBytes(length).toString('hex');
};
exports.generateRandomToken = generateRandomToken;
// Function to encrypt data using AES-256-CBC
const encryptData = (data, secretKey) => {
    const iv = crypto_1.default.randomBytes(16);
    const cipher = crypto_1.default.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
};
exports.encryptData = encryptData;
// Function to decrypt data using AES-256-CBC
const decryptData = (encryptedData, secretKey) => {
    const [ivHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto_1.default.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};
exports.decryptData = decryptData;
// Default export containing all functions
exports.default = {
    hashPassword: exports.hashPassword,
    comparePassword: exports.comparePassword,
    generateRandomToken: exports.generateRandomToken,
    encryptData: exports.encryptData,
    decryptData: exports.decryptData,
};
