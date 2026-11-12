const express = require('express')
const session = require('express-session')

const secret = process.env.SESSION_SECRET
if (!secret) throw new Error('SESSION_SECRET is not set')

const app = express()
app.use(session({ secret, resave: false, saveUninitialized: false }))

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.userId || null })
})

app.listen(3000)
