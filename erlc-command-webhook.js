const express = require('express');
const crypto = require('crypto');

const app = express();
// Render.com automatically sets the PORT environment variable
const PORT = process.env.PORT || 3000;

// Your ER:LC Server API Key - REPLACE THIS WITH YOUR ACTUAL KEY
const SERVER_API_KEY = 'YOUR_SERVER_API_KEY_HERE';

// Ed25519 Public Key for signature verification (provided by ER:LC)
const PUBLIC_KEY_BASE64 = 'MCowBQYDK2VwAyEAjSICb9pp0kHizGQtdG8ySWsDChfGqi+gyFCttigBNOA=';

// Convert base64 public key to buffer
const publicKeyBuffer = Buffer.from(PUBLIC_KEY_BASE64, 'base64');
// Extract the 32-byte Ed25519 key (skipping the SPKI wrapper)
const publicKey = publicKeyBuffer.slice(-32);

// Middleware to capture raw body
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Webhook endpoint
app.post('/webhook', async (req, res) => {
  try {
    // Get signature headers
    const signature = req.headers['x-signature-ed25519'];
    const timestamp = req.headers['x-signature-timestamp'];

    if (!signature || !timestamp) {
      console.log('Missing signature headers');
      return res.status(401).send('Missing signature headers');
    }

    // Verify signature
    const message = Buffer.concat([
      Buffer.from(timestamp, 'utf8'),
      req.rawBody
    ]);

    const signatureBuffer = Buffer.from(signature, 'hex');
    
    const isValid = crypto.verify(
      null,
      message,
      {
        key: publicKey,
        format: 'der',
        type: 'spki'
      },
      signatureBuffer
    );

    if (!isValid) {
      console.log('Invalid signature');
      return res.status(401).send('Invalid signature');
    }

    // Process the webhook data
    const data = req.body;
    console.log('Received webhook:', JSON.stringify(data, null, 2));

    // Check if it's a message event
    if (data.message && data.message.startsWith(';')) {
      const messageContent = data.message.substring(1).trim(); // Remove the semicolon
      const parts = messageContent.split(' ');
      const command = parts[0].toLowerCase();

      // Check if it's our ;t or ;talk command
      if (command === 't' || command === 'talk') {
        if (parts.length < 3) {
          console.log('Not enough arguments for command');
          return res.status(200).send('OK');
        }

        const username = parts[1];
        const message = parts.slice(2).join(' ');
        const pmCommand = `:pm ${username} ${message}`;

        console.log(`Converting command to: ${pmCommand}`);

        // Send the :pm command back to the server
        await sendCommand(pmCommand);
      }
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('Error processing webhook:', error);
    res.status(500).send('Internal server error');
  }
});

// Function to send command to ER:LC server
async function sendCommand(command) {
  try {
    const response = await fetch('https://api.policeroleplay.community/v2/server/command', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'server-key': SERVER_API_KEY
      },
      body: JSON.stringify({
        command: command
      })
    });

    const result = await response.json();
    console.log('Command response:', result);
    return result;
  } catch (error) {
    console.error('Error sending command:', error);
  }
}

// Health check endpoint
app.get('/', (req, res) => {
  res.send('ER:LC Command Webhook Server is running!');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Webhook server running on port ${PORT}`);
  console.log(`Webhook URL: https://your-app-name.onrender.com/webhook`);
  console.log(`Make sure to set your SERVER_API_KEY environment variable!`);
});
