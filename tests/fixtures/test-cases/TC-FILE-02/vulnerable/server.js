const fs = require('fs')
const path = require('path')
const express = require('express')
const multer = require('multer')

const app = express()
const upload = multer({ dest: 'tmp/' })

app.post('/api/avatar', upload.single('file'), (req, res) => {
  const target = path.join(__dirname, 'public', 'avatars', req.file.originalname)
  fs.renameSync(req.file.path, target)
  res.status(201).json({ url: '/avatars/' + req.file.originalname })
})

app.listen(3000)
