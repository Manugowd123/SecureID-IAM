// Vercel serverless entry point.
// The Express app instance itself is a valid Node request handler
// ((req, res) => ...), so exporting it directly is sufficient for
// @vercel/node to route all requests through the existing Express
// middleware/route stack unchanged.
module.exports = require('../app');
