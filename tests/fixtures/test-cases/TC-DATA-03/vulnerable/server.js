const express = require('express')
const session = require('express-session')

const app = express()
app.use(session({ secret: 'shop-session-signing-key-fixture', resave: false, saveUninitialized: false }))

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.userId || null })
})

app.listen(3000)
