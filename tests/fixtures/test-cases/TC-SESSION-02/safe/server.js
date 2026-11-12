const express = require('express')
const session = require('express-session')
const db = require('./db')

const ORIGIN = 'https://app.example.com'

const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
  })
)
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next()
  if (req.get('Origin') !== ORIGIN) return res.status(403).end()
  next()
})

app.post('/account/email', async (req, res) => {
  if (!req.session.userId) return res.status(401).end()
  await db.users.update(req.session.userId, { email: req.body.email })
  res.redirect('/account')
})

app.listen(3000)
