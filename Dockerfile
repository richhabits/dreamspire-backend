FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm ci --only=production

# Bundle app source
COPY . .

# Expose port
EXPOSE 4000

# Healthcheck for container orchestrators
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4000/api/health || exit 1

# Start the Node server
CMD [ "node", "index.js" ]
