"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// Load .env variables before any other import
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config(); // ✅ Load environment variables from .env file
// Now import everything else
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const mongoose_1 = __importDefault(require("mongoose"));
const passport_1 = __importDefault(require("passport"));
const express_session_1 = __importDefault(require("express-session"));
const connect_mongo_1 = __importDefault(require("connect-mongo")); // ✅ Session store for production
require("./config/passportConfig"); // Ensure Passport config is loaded
const authRoutes_1 = __importDefault(require("./routes/authRoutes"));
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
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
// ✅ Session setup with MongoDB store (Recommended for Production)
app.use((0, express_session_1.default)({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: connect_mongo_1.default.create({
        mongoUrl: process.env.MONGO_URI, // ✅ Use MONGO_URI from .env
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
// ✅ Root Test Route
app.get('/', (req, res) => {
    res.send('Hello World!');
});
// ✅ Global Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('Global Error:', err.message);
    res.status(500).json({ message: 'Internal Server Error', error: err.message });
});
// ✅ MongoDB Connection using MONGO_URI
const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
    throw new Error('MongoDB URI not provided in environment variables.');
}
mongoose_1.default
    .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('🔥 Connected to MongoDB successfully'))
    .catch((err) => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
});
// ✅ Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
