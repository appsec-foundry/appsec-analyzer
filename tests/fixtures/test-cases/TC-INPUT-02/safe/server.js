const express = require('express')
const { MongoClient } = require('mongodb')

const app = express()
app.use(express.json())

const db = new MongoClient(process.env.MONGO_URL).db('shop')
const reviewsCollection = db.collection('reviews')

app.post('/api/reviews/search', async (req, res) => {
  if (typeof req.body.author !== 'string') return res.status(400).end()
  res.json(await reviewsCollection.find({ author: { $eq: req.body.author } }).toArray())
})

app.listen(3000)
