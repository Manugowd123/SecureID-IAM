require('dotenv').config();

const app = require('./app');
const { testConnection } = require('./config/db');

const PORT = process.env.PORT || 3000;

/**
 * Local / traditional-host development entry point.
 *
 * The Express app itself lives in ./app.js so it can also be required
 * directly by backend/api/index.js as a Vercel serverless function
 * handler (which owns its own lifecycle and does not call listen()).
 * This file adds the two things only a persistent local process needs:
 * an up-front DB connectivity check, and app.listen().
 */
async function startServer() {
  try {
    await testConnection();
    console.log('MySQL connected successfully');
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server due to Database connection failure.');
    console.error('Details:', error.message);
    process.exit(1);
  }
}

startServer();
