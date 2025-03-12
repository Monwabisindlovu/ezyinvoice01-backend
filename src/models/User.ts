// User model file
import mongoose, { Schema, Document, Model } from 'mongoose';
import jwt from 'jsonwebtoken';

declare global {
  namespace NodeJS {
    interface ProcessEnv {
      JWT_SECRET: string;
    }
  }
}

export interface IUser extends Document {
  email: string;
  password: string;
  phone?: string;
  googleId?: string;
  name?: string;
  avatar?: string;
  securityQuestions?: { question: string; answer: string }[];
  generateJwtToken(): string;
}

const UserSchema = new Schema<IUser>(
  {
    email: { type: String, unique: true, required: true },
    phone: { type: String, unique: true, sparse: true },
    password: { type: String, required: true },
    securityQuestions: [{ question: { type: String }, answer: { type: String } }],
    googleId: { type: String, unique: true },
    name: { type: String },
    avatar: { type: String },
  },
  { timestamps: true }
);

// Attach the JWT generation method
UserSchema.methods.generateJwtToken = function (this: IUser): string {
  if (!this._id) {
    throw new Error('User ID is missing for JWT generation');
  }
  const payload = { id: this._id.toString(), email: this.email };
  const secret = process.env.JWT_SECRET || 'default-secret-key';
  console.log("Generating JWT token for user:", this.email);
  return jwt.sign(payload, secret, { expiresIn: '1h' });
};

// Remove any previously compiled model
if (mongoose.models.User) {
  delete mongoose.models.User;
}

const User: Model<IUser> = mongoose.model<IUser>('User', UserSchema);
export default User;