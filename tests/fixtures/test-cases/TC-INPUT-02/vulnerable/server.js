const express = require('express')
const { MongoClient } = require('mongodb')

const app = express()
app.use(express.json())

const db = new MongoClient(process.env.MONGO_URL).db('shop')
const reviewsCollection = db.collection('reviews')

app.post('/api/reviews/search', async (req, res) => {
  res.json(await reviewsCollection.find({ author: req.body.author }).toArray())
})

app.listen(3000)
