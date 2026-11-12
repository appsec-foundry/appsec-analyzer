const express = require('express')
const session = require('express-session')
const db = require('./db')

const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'none' }
  })
)

app.post('/account/email', async (req, res) => {
  if (!req.session.userId) return res.status(401).end()
  await db.users.update(req.session.userId, { email: req.body.email })
  res.redirect('/account')
})

app.listen(3000)
