const bcrypt = require('bcrypt')
const crypto = require('crypto')
const express = require('express')
const { rateLimit } = require('express-rate-limit')
const db = require('./db')
const { requireLogin, startSession } = require('./session')

const app = express()
app.use(express.json())

const unusedHash = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 12)
const attempts = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 })

app.post('/api/login', attempts, async (req, res) => {
  const user = await db.users.findOne({ email: req.body.email })
  const valid = await bcrypt.compare(String(req.body.password), user ? user.passwordHash : unusedHash)
  if (!user || !valid) return res.status(401).json({ error: 'E-mail address or password is wrong' })
  startSession(req, user)
  res.status(204).end()
})

app.post('/api/change-password', requireLogin, attempts, async (req, res) => {
  const user = await db.users.findByPk(req.user.id)
  if (!(await bcrypt.compare(String(req.body.currentPassword), user.passwordHash))) {
    return res.status(403).json({ error: 'The current password is wrong' })
  }
  await db.users.update(user.id, { passwordHash: await bcrypt.hash(req.body.newPassword, 12) })
  res.status(204).end()
})

app.listen(3000)
