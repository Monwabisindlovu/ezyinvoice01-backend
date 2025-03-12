declare global {
    namespace NodeJS {
      interface ProcessEnv {
        GOOGLE_CLIENT_ID: string; // Required string for Google Client ID
        JWT_SECRET: string; // Required string for JWT Secret
      }
    }
  }