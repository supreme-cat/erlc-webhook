const express = require('express');
const nacl = require('tweetnacl');

const app = express();
// Render.com automatically sets the PORT environment variable
const PORT = process.env.PORT || 3000;

// Your ER:LC Server API Key - Get from environment variable (more secure)
const SERVER_API_KEY = process.env.SERVER_API_KEY || 'YOUR_SERVER_API_KEY_HERE';

// Ed25519 Public Key for signature verification (provided by ER:LC)
const PUBLIC_KEY_BASE64 = 'MCowBQYDK2VwAyEAjSICb9pp0kHizGQtdG8ySWsDChfGqi+gyFCttigBNOA=';

// Convert base64 public key to buffer and extract the raw 32-byte Ed25519 key
const publicKeyBuffer = Buffer.from(PUBLIC_KEY_BASE64, 'base64');
// Extract the 32-byte Ed25519 key (skipping the SPKI wrapper which is first 12 bytes)
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

    // Verify signature using tweetnacl
    const message = Buffer.concat([
      Buffer.from(timestamp, 'utf8'),
      req.rawBody
    ]);

    const signatureBuffer = Buffer.from(signature, 'hex');
    
    // Use tweetnacl for Ed25519 verification
    const isValid = nacl.sign.detached.verify(
      message,
      signatureBuffer,
      publicKey
    );

    if (!isValid) {
      console.log('Invalid signature');
      return res.status(401).send('Invalid signature');
    }

    // Process the webhook data
    const data = req.body;
    console.log('Received webhook:', JSON.stringify(data, null, 2));

    // Check if we have events array
    if (data.events && Array.isArray(data.events)) {
      for (const event of data.events) {
        // Check if it's a CustomCommand event
        if (event.event === 'CustomCommand' && event.data) {
          const command = event.data.command;
          const argument = event.data.argument;

          console.log(`Custom command detected: ${command} with argument: ${argument}`);

          // Check if it's our ;t or ;talk command
          if (command === 't' || command === 'talk') {
            const parts = argument.trim().split(' ');
            
            if (parts.length < 2) {
              console.log('Not enough arguments for command. Need: username message');
              continue;
            }

            const username = parts[0];
            const message = parts.slice(1).join(' ');
            const pmCommand = `:pm ${username} ${message}`;

            console.log(`Converting command to: ${pmCommand}`);

            // Send the :pm command back to the server
            await sendCommand(pmCommand);
          }
        }
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
    console.log(`Sending command to ER:LC API: "${command}"`);
    console.log(`Using API key: ${SERVER_API_KEY.substring(0, 10)}...`);
    
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

    console.log(`API Response Status: ${response.status} ${response.statusText}`);

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`API Error Response: ${errorText}`);
      return { error: true, status: response.status, message: errorText };
    }

    const result = await response.json();
    console.log('Command response:', JSON.stringify(result, null, 2));
    return result;
  } catch (error) {
    console.error('Error sending command:', error.message);
    console.error('Full error:', error);
    return { error: true, message: error.message };
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
