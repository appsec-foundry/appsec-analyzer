const bcrypt = require('bcrypt')
const express = require('express')
const db = require('./db')
const { requireLogin, startSession } = require('./session')

const app = express()
app.use(express.json())

app.post('/api/login', async (req, res) => {
  const user = await db.users.findOne({ email: req.body.email })
  if (!user) return res.status(404).json({ error: 'No account uses this e-mail address' })
  if (!(await bcrypt.compare(req.body.password, user.passwordHash))) {
    return res.status(401).json({ error: 'Wrong password' })
  }
  startSession(req, user)
  res.status(204).end()
})

app.post('/api/change-password', requireLogin, async (req, res) => {
  await db.users.update(req.user.id, { passwordHash: await bcrypt.hash(req.body.newPassword, 12) })
  res.status(204).end()
})

app.listen(3000)
