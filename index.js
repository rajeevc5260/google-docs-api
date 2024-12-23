import express from 'express';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import cors from 'cors'; 

dotenv.config();

const app = express();
const PORT = 3000;

// In-memory map for storing user tokens
// Format: { userId: { accessToken, refreshToken, expiresAt } }
const authMap = new Map();

// Enable CORS for all routes
app.use(cors());

// Middleware
app.use(express.json());

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, CLIENT_URL } = process.env;

// Helper function to refresh the access token
async function refreshAccessToken(refreshToken) {
    try {
        const res = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                refresh_token: refreshToken,
                grant_type: 'refresh_token',
            }),
        });

        if (!res.ok) {
            const error = await res.json();
            console.error('Error refreshing token:', error);
            throw new Error('Failed to refresh token');
        }

        return await res.json();
    } catch (error) {
        console.error('Refresh token error:', error);
        throw error;
    }
}

// Helper function to decode an access token
function decodeAccessToken(accessToken) {
    try {
        const payload = JSON.parse(
            Buffer.from(accessToken.split('.')[1], 'base64').toString('utf-8')
        );
        return payload;
    } catch (error) {
        console.error('Error decoding access token:', error);
        return null;
    }
}

// API to handle Google Auth and store tokens in authMap
app.post('/auth/google', async (req, res) => {
    const { code, userId } = req.body;

    if (!code || !userId) {
        return res.status(400).json({ error: 'Missing authorization code or userId' });
    }

    try {
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                redirect_uri: `${CLIENT_URL}/auth/google/callback`,
                code,
                grant_type: 'authorization_code',
            }),
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json();
            console.error('Error fetching access token:', errorData);
            return res.status(tokenResponse.status).json({ error: errorData.error });
        }

        const tokenData = await tokenResponse.json();

        // Store tokens in authMap
        const expiresAt = new Date(Date.now() + tokenData.expires_in * 1000);
        authMap.set(userId, {
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            expiresAt,
        });

        console.log(`Tokens stored for user: ${userId}`, authMap.get(userId));

        return res.status(200).json({
            message: 'Authentication successful',
            tokens: authMap.get(userId),
        });
    } catch (error) {
        console.error('Error during authentication:', error.message);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// API to fetch a Google Doc
app.get('/google-doc', async (req, res) => {
    const { documentId, userId } = req.query;

    if (!documentId || !userId) {
        return res.status(400).json({
            error: 'Missing documentId or userId',
        });
    }

    const userTokens = authMap.get(userId);

    if (!userTokens) {
        return res.status(401).json({
            error: 'User not authenticated. Authenticate first.',
        });
    }

    let { accessToken, refreshToken, expiresAt } = userTokens;

    try {
        // Check if the access token has expired
        if (new Date() > expiresAt) {
            console.log('Access token expired, refreshing...');
            const refreshedData = await refreshAccessToken(refreshToken);

            accessToken = refreshedData.access_token;
            expiresAt = new Date(Date.now() + refreshedData.expires_in * 1000);

            // Update tokens in authMap
            authMap.set(userId, { accessToken, refreshToken, expiresAt });

            console.log('Access token refreshed:', accessToken);
        }

        // Use the access token to fetch the document
        const response = await fetch(`https://docs.googleapis.com/v1/documents/${documentId}`, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Error fetching Google Doc:', errorData);
            return res.status(response.status).json({
                error: errorData.error.message,
                details: errorData,
            });
        }

        const docData = await response.json();
        // console.log('Google Doc Data:', docData);

        return res.status(200).json({
            message: 'Google Doc fetched successfully',
            data: docData,
        });
    } catch (error) {
        console.error('Error:', error.message);
        return res.status(500).json({
            error: 'Internal server error',
            details: error.message,
        });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
