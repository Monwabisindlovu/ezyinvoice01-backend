"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const mongoose_1 = __importDefault(require("mongoose"));
const passport_1 = __importDefault(require("passport"));
const express_session_1 = __importDefault(require("express-session"));
const connect_mongo_1 = __importDefault(require("connect-mongo")); // ✅ Session store for production
require("./config/passportConfig"); // Ensure Passport config is loaded
const authRoutes_1 = __importDefault(require("./routes/authRoutes"));
dotenv_1.default.config();
const app = (0, express_1.default)();
// ✅ Allowed origins for CORS
const allowedOrigins = [
    'http://localhost:3000', // Local development
    'https://ezyinvoice01.vercel.app', // Deployed frontend
    'https://accounts.google.com' // ✅ Allow Google OAuth
];
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // ✅ Important: Allows cookies/session sharing
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};
// ✅ Apply CORS middleware before other middlewares
app.use((0, cors_1.default)(corsOptions));
app.options('*', (0, cors_1.default)(corsOptions));
// ── NEW: Relax COOP for local development ──
app.use((req, res, next) => {
    // Allow popups and cross-origin messaging (needed for Google sign-in)
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    next();
});
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
// ✅ Set security headers properly (disable COOP for Google OAuth)
app.use((req, res, next) => {
    if (req.path.startsWith('/auth/google') || req.path.startsWith('/api/auth/google')) {
        // ✅ Remove restrictive headers for Google OAuth
        res.removeHeader('Cross-Origin-Opener-Policy');
        res.removeHeader('Cross-Origin-Embedder-Policy');
    }
    next();
});
// ✅ Session setup with MongoDB store (Recommended for Production)
app.use((0, express_session_1.default)({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: connect_mongo_1.default.create({
        mongoUrl: process.env.MONGO_URI || 'mongodb://localhost/ezyinvoice',
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production', // ✅ Enable only in production
        httpOnly: true,
        sameSite: 'lax',
    },
}));
// ✅ Initialize Passport.js for authentication
app.use(passport_1.default.initialize());
app.use(passport_1.default.session());
// ✅ Auth Routes
app.use('/api/auth', authRoutes_1.default);
// ✅ Google OAuth Routes
app.get('/auth/google', passport_1.default.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport_1.default.authenticate('google', { failureRedirect: '/login', session: false }), (req, res) => {
    try {
        if (!req.user) {
            res.status(400).json({ message: 'User authentication failed' });
            return; // ✅ Ensure function exits properly
        }
        const user = req.user; // ✅ Ensure req.user exists
        const accessToken = user.generateJwtToken();
        // ✅ Redirect dynamically based on environment
        const frontendURL = process.env.FRONTEND_URL || 'http://localhost:3000';
        res.redirect(`${frontendURL}?token=${accessToken}`);
        return; // ✅ Explicit return to satisfy TypeScript
    }
    catch (error) {
        console.error('Google Auth Error:', error);
        res.status(500).json({ message: 'Error during authentication', error: error instanceof Error ? error.message : 'Unknown error' });
        return; // ✅ Ensure function always returns void
    }
});
// ✅ Root Test Route
app.get('/', (req, res) => {
    res.send('Hello World!');
});
// ✅ Global Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('Global Error:', err.message);
    res.status(500).json({ message: 'Internal Server Error', error: err.message });
});
// ✅ MongoDB Connection
mongoose_1.default
    .connect(process.env.MONGO_URI || 'mongodb://localhost/ezyinvoice', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('✅ MongoDB connected'))
    .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});
// ✅ Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
