import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import User from '../models/User'; 

// Load environment variables
dotenv.config();

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  throw new Error('❌ Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in environment variables');
}

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:5000/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('✅ Google OAuth Profile:', profile);
        console.log('🔑 Access Token:', accessToken);

        const email = profile.emails?.[0]?.value || '';
        const avatar = profile.photos?.[0]?.value || '';

        // Check if a user already exists based on email
        let user = await User.findOne({ email }).exec();

        if (!user) {
          // If user does not exist, create a new one
          user = new User({
            email,
            googleId: profile.id,
            name: profile.displayName,
            avatar,
          });
          await user.save();
          console.log('🆕 New user created:', user);
        } else {
          console.log('✅ Existing user found:', user);
        }

        // Ensure the user instance is a valid Mongoose document
        if (!user || !(user instanceof mongoose.Document)) {
          return done(new Error('⚠️ User instance is invalid'), false);
        }

        return done(null, user);
      } catch (error) {
        console.error('❌ Error during OAuth authentication:', error);
        return done(error, false);
      }
    }
  )
);

// Serialization and Deserialization
passport.serializeUser((user: any, done) => {
  console.log('🔄 Serializing user ID:', user.id);
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await User.findById(id).exec();
    if (!user) {
      return done(null, false);
    }
    console.log('🔄 Deserialized user:', user);
    done(null, user);
  } catch (error) {
    console.error('❌ Error deserializing user:', error);
    done(error, false);
  }
});

export default passport;