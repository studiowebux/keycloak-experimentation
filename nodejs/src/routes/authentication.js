import express from 'express';
import { client } from '../keycloak.js';

const router = express.Router();

export default function routes(passport) {
  router.get('/auth/callback', (req, res, next) => {
    passport.authenticate('oidc', {
      successRedirect: '/profile',
      failureRedirect: '/'
    })(req, res, next);
  });

  router.get('/auth/logout/callback', (req, res) => {
    req.logout(() => res.redirect('/'));
  });

  router.get('/auth/logout', (_req, res) => {
    res.redirect(client.endSessionUrl());
  });

  router.get('/auth/login', (req, res, next) => {
    passport.authenticate('oidc')(req, res, next);
  });

  router.get('/not-logged-in', (req, res) => {
    if (req.isAuthenticated()) return res.redirect('/');
    res.render('pages/not-logged-in', {
      isAuthenticated: req.isAuthenticated()
    });
  });

  return router;
}
