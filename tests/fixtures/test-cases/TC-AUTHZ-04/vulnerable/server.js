const express = require('express')
const { requireLogin } = require('./auth')
const db = require('./db')

const app = express()

app.get('/api/invoices', requireLogin, async (req, res) => {
  const tenantId = req.get('X-Tenant-Id')
  res.json(await db.invoices.findAll({ where: { tenantId } }))
})

app.listen(3000)
