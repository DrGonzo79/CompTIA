// server.js
const express = require('express');
const OpenAI = require('openai');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const openai = new OpenAI({
	apiKey: process.env.OPENAI_API_KEY,
});

app.post('/api/text-to-speech', async (req, res) => {
	try {
		const { text, voice = 'alloy' } = req.body;

		const mp3Response = await openai.audio.speech.create({
			model: 'tts-1',
			voice: voice,
			input: text,
		});

		// Convert audio buffer to base64
		const buffer = Buffer.from(await mp3Response.arrayBuffer());
		const base64Audio = buffer.toString('base64');

		res.json({ audio: base64Audio });
	} catch (error) {
		console.error('TTS Error:', error);
		res.status(500).json({ error: 'Text-to-speech conversion failed' });
	}
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Server running on port ${PORT}`);
});
