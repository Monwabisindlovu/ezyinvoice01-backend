export interface User {
    id: string;
    email: string;
    passwordHash: string;
    fullName: string;
    role: 'user' | 'admin';
    createdAt: Date | string;  // Consider using string for date
    updatedAt: Date | string;  // Consider using string for date
  }
  
  export interface UserLogin {
    emailOrPhone: string; 
    password: string;
  }
  
  export interface UserSignup {
    email: string;
    password: string;
    fullName: string;
    role: 'user' | 'admin';
    phone?: string; // Phone is now optional
  }
  
  export interface UserResponse {
    id: string;
    email: string;
    fullName: string;
    role: 'user' | 'admin';
  }
  
  export interface UserTokenPayload {
    userId: string;
    role?: 'user' | 'admin';  // Optional field, can include role if needed
  }
  
  export interface UpdateUserProfile {
    email?: string;
    fullName?: string;
    password?: string;
    phone?: string; // Added optional phone field for profile updates
  }