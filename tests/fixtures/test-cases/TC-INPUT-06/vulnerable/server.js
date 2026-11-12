const express = require('express')
const libxml = require('libxmljs2')

const app = express()
app.use(express.text({ type: 'application/xml' }))

app.post('/api/import', (req, res) => {
  const doc = libxml.parseXml(req.body, { noent: true })
  res.json({ items: doc.find('//item').length })
})

app.listen(3000)
