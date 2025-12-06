import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const port = process.env.PORT || 2000;
app.use(cors())

//  Public Api
app.get("/", async (req, res) => res.send("Server is getting!"))
app.listen(port, () => console.log(`Server listening ${port}.`))