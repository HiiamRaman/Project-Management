import dotenv from 'dotenv'
import express from 'express'
dotenv.config()


const app = express()
const port = 3000

app.get('/', (req, res) => {
  res.send('Hello Raman!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${process.env.PORT}`)
})
