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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Session setup with MongoDB store (Recommended for Production)
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key', // Use a fallback secret if not set
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI, // ✅ Use MONGO_URI from .env
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

// ✅ Root Test Route
app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

// ✅ Global Error Handling Middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Global Error:', err.message);
  res.status(500).json({ message: 'Internal Server Error', error: err.message });
});

// ✅ MongoDB Connection using MONGO_URI
const mongoURI = process.env.MONGO_URI; // Get MONGO_URI from .env
if (!mongoURI) {
  throw new Error('MongoDB URI not provided in environment variables.'); // Throw error if MONGO_URI is missing
}

mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  } as any)
  .then(() => console.log('🔥 Connected to MongoDB successfully'))
  .catch((err) => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
  });

// ✅ Start the Server
const PORT = process.env.PORT || 5000; // Use PORT from environment or default to 5000
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
