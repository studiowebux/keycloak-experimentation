import { Strategy } from 'openid-client';
import passport from 'passport';

export function initPassport(app, client) {
  app.use(passport.authenticate('session'));

  passport.use(
    'oidc',
    new Strategy({ client }, (token, _userInfo, done) => {
      return done(null, token.claims());
    })
  );

  passport.serializeUser(function (user, done) {
    done(null, user);
  });
  passport.deserializeUser(function (user, done) {
    done(null, user);
  });

  return { app, passport };
}

export function isAuthenticated(req, res, next) {
  req.isAuthenticated() ? next() : res.redirect('/not-logged-in');
}
