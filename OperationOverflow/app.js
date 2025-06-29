const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(express.static('public'));

const schema = buildSchema(`
  type Query {
    guessNumber(number: Int!): GuessResult
  }
  
  type GuessResult {
    correct: Boolean!
    message: String!
    flag: String
  }
`);

const sessionStore = new Map();

function generateFlag() {
  return `BMCTF{4l14s_br34k_l1m1ts}`;
}

function generateSecureRandomNumber(min, max) {
  if (min >= max) {
    throw new Error('Min must be less than max');
  }
  
  const range = max - min + 1;
  const randomBytes = crypto.randomBytes(4);
  const randomValue = randomBytes.readUInt32BE(0);
  
  return min + (randomValue % range);
}

function sessionRateLimiter(req, res, next) {
  const sessionId = req.session.id;
  const now = Date.now();
  
  if (!sessionStore.has(sessionId)) {
    sessionStore.set(sessionId, {
      requests: 0,
      resetTime: now + 60000, 
      targetNumber: generateSecureRandomNumber(1, 100000),
      lastRequest: now,
      blockedUntil: 0,
      concurrent: 0 
    });
  }
  
  const session = sessionStore.get(sessionId);
  
  session.concurrent += 1;
  
  try {
    if (session.blockedUntil > now) {
      const timeRemaining = Math.ceil((session.blockedUntil - now) / 1000);
      session.concurrent -= 1; // Release our lock
      return res.status(429).json({
        errors: [{
          message: `Rate limit exceeded. Try again in ${timeRemaining} seconds.`
        }]
      });
    }
    
    if (now > session.resetTime) {
      session.requests = 0;
      session.resetTime = now + 60000; 
    }
    
    if (session.requests >= 10) {
      session.blockedUntil = now + 120000; 
      session.concurrent -= 1; 
      return res.status(429).json({
        errors: [{
          message: "Rate limit exceeded. Try again in 120 seconds."
        }]
      });
    }
    
    session.requests++;
    session.lastRequest = now;
    
    const requestTimeout = setTimeout(() => {
      if (session.concurrent > 0) session.concurrent -= 1;
    }, 30000); 
    
    const originalEnd = res.end;
    res.end = function() {
      clearTimeout(requestTimeout);
      if (session.concurrent > 0) session.concurrent -= 1;
      return originalEnd.apply(this, arguments);
    };
    
    next();
  } catch (error) {
    if (session.concurrent > 0) session.concurrent -= 1;
    return res.status(500).json({
      errors: [{
        message: "Server error"
      }]
    });
  }
}

function complexityLimiter(req, res, next) {
  if (!req.body) {
    return next();
  }
  
  const query = req.body.query || '';
  
  const operationCount = (query.match(/guessNumber\(/g) || []).length;
  
  if (operationCount > 10000) {
    return res.status(400).json({
      errors: [{
        message: "Excessive query complexity"
      }]
    });
  }
  
  next();
}

const root = {
  guessNumber: (args, context) => {
    const number = args.number;
    const sessionId = context.session.id;
    
    if (!sessionStore.has(sessionId)) {
      return {
        correct: false,
        message: "Error: Session not found",
        flag: null
      };
    }
    
    
    if (number === sessionStore.get(sessionId).targetNumber) {
      const flag = generateFlag();
      return {
        correct: true,
        message: "Correct! You found the number.",
        flag: flag
      };
    } else {
      return {
        correct: false,
        message: "Incorrect guess.",
        flag: null
      };
    }
  }
};

app.get('/', (req, res) => {
  if (!sessionStore.has(req.session.id)) {
    sessionStore.set(req.session.id, {
      requests: 0,
      resetTime: Date.now() + 60000,
      targetNumber: generateSecureRandomNumber(1, 100000),
      lastRequest: Date.now(),
      blockedUntil: 0,
      concurrent: 0
    });
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use('/graphql', express.json());
app.use('/graphql', sessionRateLimiter);
app.use('/graphql', complexityLimiter);

app.use('/graphql', (req, res, next) => {
  if (req.method === 'GET') {
    return res.status(405).json({
      errors: [{
        message: "For this CTF challenge, GraphQL queries must be sent via POST requests"
      }]
    });
  }
  
  return graphqlHTTP({
    schema: schema,
    rootValue: root,
    graphiql: false,  
    context: { session: req.session }
  })(req, res, next);
});

setInterval(() => {
  const now = Date.now();
  
  sessionStore.forEach((session, sessionId) => {
    if (now - session.lastRequest > 900000) {
      sessionStore.delete(sessionId);
    }
  });
}, 300000); 

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Homepage available at http://localhost:${PORT}/`);
  console.log(`GraphQL endpoint available at http://localhost:${PORT}/graphql`);
});
