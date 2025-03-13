# Use an official Node.js image as a base
FROM node:16

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json to install dependencies (before copying other files)
COPY package*.json ./

# Install dependencies
RUN npm install

# Add permission to the TypeScript compiler binary
RUN chmod +x /app/node_modules/.bin/tsc

# Optionally set the user to root (if needed for permission issues)
USER root

# Copy the rest of the application code
COPY . .

# Run the build command
RUN npm run build

# Expose the port that the app will run on
EXPOSE 3000

# Start the app (or use your start command)
CMD ["npm", "start"]
