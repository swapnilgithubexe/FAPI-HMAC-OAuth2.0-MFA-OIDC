// Import necessary modules
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Configuration
const OIDC_PROVIDER = 'https://openid-provider.com';
const CLIENT_ID = 'your-client-id';
const CLIENT_SECRET = 'your-client-secret';
const REDIRECT_URI = 'http://localhost:3000/callback';
const SHARED_SECRET_KEY = 'shared-secret-key';

// Simulated financial data to log
const financialData = { userId: 12345, transaction: 'debit', amount: 2500 };

// Step 1: Redirect user to OpenID Connect login
app.get('/login', (req, res) => {
  const loginUrl = `${OIDC_PROVIDER}/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=openid%20email%20profile&response_type=code`;
  res.redirect(loginUrl);
});

// Step 2: Callback to handle OpenID authentication
app.get('/callback', async (req, res) => {
  const authCode = req.query.code;

  try {
    // Exchange authorization code for tokens
    const tokenResponse = await axios.post(`${OIDC_PROVIDER}/token`, {
      code: authCode,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code'
    });

    const idToken = tokenResponse.data.id_token;
    const accessToken = tokenResponse.data.access_token;

    // Verify ID token (implementation omitted for brevity)

    // Proceed to log financial data
    const hmac = crypto.createHmac('sha256', SHARED_SECRET_KEY)
      .update(JSON.stringify(financialData))
      .digest('hex');

    const headers = {
      Authorization: `Bearer ${accessToken}`,
      'X-Signature': hmac
    };

    // Call API to log financial data
    const apiResponse = await axios.post('http://localhost:3000/financial/log', financialData, { headers });
    res.send(`Financial data logged: ${JSON.stringify(apiResponse.data)}`);
  } catch (err) {
    console.error('Error during callback:', err.message);
    res.status(500).send('Authentication failed');
  }
});

// Step 3: API endpoint to log financial data securely
app.post('/financial/log', (req, res) => {
  const receivedHmac = req.headers['x-signature'];
  const generatedHmac = crypto.createHmac('sha256', SHARED_SECRET_KEY)
    .update(JSON.stringify(req.body))
    .digest('hex');

  // Verify HMAC signature
  if (!crypto.timingSafeEqual(Buffer.from(receivedHmac), Buffer.from(generatedHmac))) {
    return res.status(401).send('Invalid HMAC signature');
  }

  console.log('Financial data logged:', req.body);
  res.status(200).send('Financial data successfully logged.');
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});