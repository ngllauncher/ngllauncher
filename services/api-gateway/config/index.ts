export const config = {
  port: process.env.PORT || 3000,
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10)
  },
  services: {
    auth: {
      url: process.env.AUTH_SERVICE_URL || 'http://auth-service:3001'
    },
    twitter: {
      url: process.env.TWITTER_SERVICE_URL || 'http://twitter-service:3002'
    },
    blockchain: {
      url: process.env.BLOCKCHAIN_SERVICE_URL || 'http://blockchain-service:3004'
    },
    storage: {
      url: process.env.STORAGE_SERVICE_URL || 'http://storage-service:3005'
    }
  }
}; 