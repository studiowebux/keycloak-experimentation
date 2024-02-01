import express from 'express';
import { isAuthenticated } from '../passport.js';

const router = express.Router();

router.get('/profile', isAuthenticated, (req, res) => {
  res.render('pages/profile', {
    profile: {
      username: req.user.preferred_username,
      name: req.user.name,
      email: req.user.email,
      email_verified: req.user.email_verified
    },
    isAuthenticated: req.isAuthenticated()
  });
});

export default router;
