const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const JWT_SECRET = process.env.JWT_SECRET || 'loveIs';
const port = process.env.PORT || 3002;

const expressApp = express();
const server = http.createServer(expressApp);
const io = new Server(server, {
  cors: {
    origin: ['http://localhost:6969', process.env.CLIENT_URL].filter(Boolean),
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

expressApp.use(cors({
  origin: ['http://localhost:6969', process.env.CLIENT_URL].filter(Boolean),
  credentials: true,
}));
expressApp.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:123456@localhost:5555/message',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Initialize database tables
async function initializeDatabase() {
  try {
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT FROM pg_class WHERE relname = 'users_id_seq' AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')) THEN
          CREATE SEQUENCE users_id_seq;
        END IF;
      END $$;

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY DEFAULT nextval('users_id_seq'),
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );

      DO $$
      BEGIN
        IF NOT EXISTS (SELECT FROM pg_class WHERE relname = 'messages_id_seq' AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')) THEN
          CREATE SEQUENCE messages_id_seq;
        END IF;
      END $$;

      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY DEFAULT nextval('messages_id_seq'),
        user_id INTEGER REFERENCES users(id),
        content TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        recipient_id INTEGER REFERENCES users(id),
        is_edited BOOLEAN DEFAULT FALSE
      );
    `);
    console.log('Database and tables initialized');
  } catch (err) {
    console.error('Database initialization failed:', err.message, err.stack);
  }
}

initializeDatabase().then(() => {
  console.log('Database initialization complete');
}).catch((err) => {
  console.error('Error during database initialization:', err.message);
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'Token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Invalid token:', err.message);
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

expressApp.post('/register', async (req, res) => {
  const { username, password } = req.body;
  console.log('Register attempt:', { username });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user });
  } catch (err) {
    console.error('Register error:', err);
    res.status(400).json({ error: 'Username already exists or invalid data' });
  }
});

expressApp.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt:', { username });
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) {
      console.log('User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Password mismatch for user:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

expressApp.get('/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

expressApp.get('/messages', authenticateToken, async (req, res) => {
  const { selectedUserId, limit = 15, offset = 0 } = req.query;
  const numericSelectedUserId = parseInt(selectedUserId, 10);
  const numericLimit = parseInt(limit, 10);
  const numericOffset = parseInt(offset, 10);
  console.log('Messages request params:', { userId: req.user.id, selectedUserId: numericSelectedUserId, limit: numericLimit, offset: numericOffset });
  if (isNaN(numericSelectedUserId)) {
    console.error('Invalid selectedUserId:', selectedUserId);
    return res.status(400).json({ error: 'Invalid selectedUserId' });
  }
  try {
    const result = await pool.query(
      'SELECT m.id::text, m.content, m.timestamp, u.username, r.username AS recipient_username, m.user_id, m.recipient_id, m.is_edited ' +
      'FROM messages m ' +
      'JOIN users u ON m.user_id = u.id ' +
      'LEFT JOIN users r ON m.recipient_id = r.id ' +
      'WHERE (m.user_id = $1 AND m.recipient_id = $2) OR (m.user_id = $2 AND m.recipient_id = $1) ' +
      'ORDER BY m.timestamp DESC ' +
      'LIMIT $3 OFFSET $4',
      [req.user.id, numericSelectedUserId, numericLimit, numericOffset]
    );
    console.log('Messages fetched from DB:', result.rows);
    res.json({ messages: result.rows, hasMore: result.rowCount === numericLimit });
  } catch (err) {
    console.error('Messages error:', err.message, err.stack);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

expressApp.get('/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username FROM users WHERE id != $1', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error('Users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

expressApp.put('/edit-message', authenticateToken, async (req, res) => {
  const { messageId, content } = req.body;
  try {
    const result = await pool.query(
      'UPDATE messages SET content = $1, is_edited = TRUE WHERE id = $2 AND user_id = $3 RETURNING id::text, user_id, recipient_id, content, timestamp, is_edited',
      [content, messageId, req.user.id]
    );
    if (result.rowCount === 0) {
      return res.status(403).json({ error: 'Message not found or not authorized' });
    }
    const message = result.rows[0];
    const recipient = await pool.query('SELECT username FROM users WHERE id = $1', [message.recipient_id]);
    const sender = await pool.query('SELECT username FROM users WHERE id = $1', [message.user_id]);
    const messageData = {
      id: message.id,
      content: message.content,
      timestamp: message.timestamp,
      username: sender.rows[0]?.username || 'Unknown',
      recipient_username: recipient.rows[0]?.username || 'Unknown',
      user_id: message.user_id,
      recipient_id: message.recipient_id,
      is_edited: message.is_edited,
    };
    io.to(message.user_id.toString()).emit('edit_message', messageData);
    io.to(message.recipient_id.toString()).emit('edit_message', messageData);
    res.json(messageData);
  } catch (err) {
    console.error('Edit message error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

expressApp.delete('/delete-message/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM messages WHERE id = $1 AND user_id = $2 RETURNING id::text, user_id, recipient_id',
      [id, req.user.id]
    );
    if (result.rowCount === 0) {
      return res.status(403).json({ error: 'Message not found or not authorized' });
    }
    const message = result.rows[0];
    io.to(message.user_id.toString()).emit('delete_message', { id: message.id });
    io.to(message.recipient_id.toString()).emit('delete_message', { id: message.id });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete message error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('send_message', async (data) => {
    const { content, userId, recipientId, username } = data;
    try {
      const result = await pool.query(
        'INSERT INTO messages (user_id, recipient_id, content, timestamp, is_edited) VALUES ($1, $2, $3, NOW(), FALSE) RETURNING id::text, user_id, recipient_id, content, timestamp, is_edited',
        [userId, recipientId, content]
      );
      const message = result.rows[0];
      const recipient = await pool.query('SELECT username FROM users WHERE id = $1', [recipientId]);
      const recipientUsername = recipient.rows[0]?.username || 'Unknown';
      const messageData = {
        id: message.id,
        content: message.content,
        timestamp: message.timestamp,
        username,
        recipient_username: recipientUsername,
        user_id: message.user_id,
        recipient_id: message.recipient_id,
        is_edited: message.is_edited,
      };
      io.to(recipientId.toString()).emit('receive_message', messageData);
      socket.emit('message_sent', messageData);
    } catch (err) {
      console.error('Send message error:', err);
    }
  });

  socket.on('join', (userId) => {
    socket.join(userId.toString());
    console.log(`User ${userId} joined room`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});