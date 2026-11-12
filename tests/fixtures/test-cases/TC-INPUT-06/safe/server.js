const express = require('express')
const libxml = require('libxmljs2')

const app = express()
app.use(express.text({ type: 'application/xml', limit: '100kb' }))

app.post('/api/import', (req, res) => {
  const doc = libxml.parseXml(req.body, { noent: false, nonet: true, dtdload: false })
  res.json({ items: doc.find('//item').length })
})

app.listen(3000)
