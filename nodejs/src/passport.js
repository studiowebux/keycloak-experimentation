import { Strategy, TokenSet } from 'openid-client';
import passport from 'passport';
import { client, refreshToken } from './keycloak.js';

export function initPassport(app, client) {
  app.use(passport.authenticate('session'));

  passport.use(
    'oidc',
    new Strategy({ client }, (tokenSet, _userInfo, done) => {
      return done(null, tokenSet);
    })
  );

  passport.serializeUser(function (token, done) {
    // console.debug('SERIALIZE', Object.keys(token));
    done(null, token);
  });
  passport.deserializeUser(function (token, done) {
    // console.debug('DESERIALIZE', Object.keys(token));
    done(null, { userinfo: new TokenSet(token).claims(), token });
  });

  return { app, passport };
}

export async function isAuthenticated(req, res, next) {
  console.log(
    'isAuth',
    req.isAuthenticated(),
    !new TokenSet(req.user?.token).expired()
  );
  req.isAuthenticated() && !new TokenSet(req.user.token).expired()
    ? next()
    : await refresh(req, res, next);
}

export async function refresh(req, res, next) {
  try {
    // console.log('refresh');
    if (req.user) {
      // console.debug('ACCESS TOKEN IS EXPIRED');
      const rawTokenSet = await refreshToken(req.user.token.refresh_token);
      const tokenSet = new TokenSet(rawTokenSet);
      tokenSet.expires_at = tokenSet.expires_at || tokenSet.claims().exp;
      // console.log(tokenSet);
      // console.log('NEW TOKEN SET', tokenSet);
      req.session.passport.user = tokenSet;

      // console.log('SESSION', req.session.passport.user);
      return req.session.save(function (err) {
        // session saved
        // console.error('SAVING SESSION', err);
        req.user.token = req.session.passport.user;
        req.user.userinfo = tokenSet.claims();
        // console.log('USER', req.user);
        return next();
      });
    } 

    throw new Error("Unable to refresh the token. You must sign in.")
  } catch (e) {
    console.error(e);
    return res.redirect(client.endSessionUrl());
  }
}
