// Load .env variables before any other import
import dotenv from 'dotenv';
dotenv.config(); // ✅ Load environment variables from .env file

// Now import everything else
import express, { Request, Response, NextFunction } from 'express';
import cors, { CorsOptions } from 'cors';
import mongoose from 'mongoose';
import passport from 'passport';
import session from 'express-session';
import MongoStore from 'connect-mongo'; // ✅ Session store for production
import './config/passportConfig'; // Ensure Passport config is loaded
import authRoutes from './routes/authRoutes';

const app = express();

// ✅ Allowed origins for CORS
const allowedOrigins: string[] = [
  'http://localhost:3000', // Local development
  'https://ezyinvoice01.vercel.app', // Deployed frontend
  'https://accounts.google.com' // ✅ Allow Google OAuth
];

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // ✅ Important: Allows cookies/session sharing
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

// ✅ Apply CORS middleware before other middlewares
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ── NEW: Relax COOP for local development ──
app.use((req, res, next) => {
  // Allow popups and cross-origin messaging (needed for Google sign-in)
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI || 'mongodb://localhost/ezyinvoice',
    }),
    cookie: {
      secure: process.env.NODE_ENV === 'production', // ✅ Enable only in production
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

// ✅ Initialize Passport.js for authentication
app.use(passport.initialize());
app.use(passport.session());

// ✅ Auth Routes
app.use('/api/auth', authRoutes);

// ✅ Google OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  (req: Request, res: Response): void => {
    try {
      if (!req.user) {
        res.status(400).json({ message: 'User authentication failed' });
        return; // ✅ Ensure function exits properly
      }

      const user = req.user as any; // ✅ Ensure req.user exists
      const accessToken = user.generateJwtToken();

      // ✅ Redirect dynamically based on environment
      const frontendURL = process.env.FRONTEND_URL || 'http://localhost:3000';
      res.redirect(`${frontendURL}?token=${accessToken}`);
      
      return; // ✅ Explicit return to satisfy TypeScript
    } catch (error: unknown) {
      console.error('Google Auth Error:', error);
      res.status(500).json({ message: 'Error during authentication', error: error instanceof Error ? error.message : 'Unknown error' });

      return; // ✅ Ensure function always returns void
    }
  }
);

// ✅ Root Test Route
app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

// ✅ Global Error Handling Middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Global Error:', err.message);
  res.status(500).json({ message: 'Internal Server Error', error: err.message });
});

// ✅ MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI || 'mongodb://localhost/ezyinvoice', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  } as any)
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err: unknown) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// ✅ Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
