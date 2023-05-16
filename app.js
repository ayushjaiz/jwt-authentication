import dotenv from 'dotenv'
dotenv.config()
import express from 'express'
import connectDb from './config/conectdb.js'
import cors from 'cors'
import userRoutes from './routes/userRoutes.js'

const app = express()
const port = process.env.port

//Cors Policy
app.use(cors())

//Database Connection
connectDb(process.env.MONGODB_URL);

//JSON
app.use(express.json())

// Load Routes
app.use('/api/user',userRoutes)

app.listen(port, () => {
    console.log(`server listening at http://localhost:${port}`)
})