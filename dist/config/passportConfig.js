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
const passport_1 = __importDefault(require("passport"));
const passport_google_oauth20_1 = require("passport-google-oauth20");
const dotenv_1 = __importDefault(require("dotenv"));
const mongoose_1 = __importDefault(require("mongoose"));
const User_1 = __importDefault(require("../models/User"));
// Load environment variables
dotenv_1.default.config();
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    throw new Error('❌ Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in environment variables');
}
passport_1.default.use(new passport_google_oauth20_1.Strategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:5000/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d;
    try {
        console.log('✅ Google OAuth Profile:', profile);
        console.log('🔑 Access Token:', accessToken);
        const email = ((_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.value) || '';
        const avatar = ((_d = (_c = profile.photos) === null || _c === void 0 ? void 0 : _c[0]) === null || _d === void 0 ? void 0 : _d.value) || '';
        // Check if a user already exists based on email
        let user = yield User_1.default.findOne({ email }).exec();
        if (!user) {
            // If user does not exist, create a new one
            user = new User_1.default({
                email,
                googleId: profile.id,
                name: profile.displayName,
                avatar,
            });
            yield user.save();
            console.log('🆕 New user created:', user);
        }
        else {
            console.log('✅ Existing user found:', user);
        }
        // Ensure the user instance is a valid Mongoose document
        if (!user || !(user instanceof mongoose_1.default.Document)) {
            return done(new Error('⚠️ User instance is invalid'), false);
        }
        return done(null, user);
    }
    catch (error) {
        console.error('❌ Error during OAuth authentication:', error);
        return done(error, false);
    }
})));
// Serialization and Deserialization
passport_1.default.serializeUser((user, done) => {
    console.log('🔄 Serializing user ID:', user.id);
    done(null, user.id);
});
passport_1.default.deserializeUser((id, done) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const user = yield User_1.default.findById(id).exec();
        if (!user) {
            return done(null, false);
        }
        console.log('🔄 Deserialized user:', user);
        done(null, user);
    }
    catch (error) {
        console.error('❌ Error deserializing user:', error);
        done(error, false);
    }
}));
exports.default = passport_1.default;
