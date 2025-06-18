import app from "./app.js"
import dotenv from "dotenv"
dotenv.config();
import mongoose from "mongoose"

const PORT = process.env.PORT || 5000

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("dB Connected")
        app.listen(PORT, () => {
            console.log(`server is running on http://localhost:${PORT}`)
        })

    })
    .catch(() => { console.log("Connection error") })



