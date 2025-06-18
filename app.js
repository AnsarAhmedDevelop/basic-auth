import express from "express"
const app = express();
import createError from 'http-errors'
import { globalErrorHandler } from "./middlewares/globalErrorHandler.js";
import authRoutes from "./routes/authRoutes.js"
//ju bhi request hai usku json may convert
app.use(express.json());
app.use(express.urlencoded({extended:true}))
app.use("/uploads", express.static("uploads"));

app.get("/", (req, res) => {
    res.json("Hello World")
})

app.post("/users", (req, res) => {
//    const error =  new Error("Something went Wrong");
//    error.status=200;
//    throw error
    throw createError(404,"Something went Wrong")
    return
    res.status(201).json({ message: "User Created" })
})

app.use("/api/auth", authRoutes)

// Global Error handler
app.use(globalErrorHandler)

export default app