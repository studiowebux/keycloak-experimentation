import expressSession from 'express-session';

const { EXPRESS_SESSION_SECRET, NODE_ENV } = process.env;

export function initSession(app) {
  // TODO: Not great for production, should use persistent storage...
  const memoryStore = new expressSession.MemoryStore();
  app.use(
    expressSession({
      secret: EXPRESS_SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
      store: memoryStore,
      cookie: { secure: NODE_ENV === 'production' ? true : false }
    })
  );
}
