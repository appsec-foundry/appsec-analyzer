const express = require('express')
const session = require('express-session')
const db = require('./db')

const app = express()
app.use(express.json())
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 * 60 * 1000 }
  })
)

app.post('/api/login', async (req, res) => {
  const user = await db.users.authenticate(req.body.email, req.body.password)
  if (!user) return res.status(401).end()
  req.session.regenerate((err) => {
    if (err) return res.status(500).end()
    req.session.userId = user.id
    res.status(204).end()
  })
})

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid')
    res.status(204).end()
  })
})

app.listen(3000)
