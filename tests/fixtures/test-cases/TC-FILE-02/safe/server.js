const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const express = require('express')
const multer = require('multer')

const app = express()
const TYPES = { 'image/png': '.png', 'image/jpeg': '.jpg' }
const upload = multer({
  dest: 'tmp/',
  limits: { fileSize: 1024 * 1024, files: 1 },
  fileFilter: (req, file, done) => done(null, file.mimetype in TYPES)
})

app.post('/api/avatar', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).end()
  const name = crypto.randomUUID() + TYPES[req.file.mimetype]
  fs.renameSync(req.file.path, path.join(__dirname, 'public', 'avatars', name))
  res.status(201).json({ url: '/avatars/' + name })
})

app.listen(3000)
