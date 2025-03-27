import express from 'express';

const router = express.Router();

// Simple health check endpoint
router.get('/', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

export default router;