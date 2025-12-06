import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ServerApiVersion } from "mongodb";

dotenv.config();
const app = express();
const port = process.env.PORT || 2000;
const uri = process.env.DB;

app.use(cors())
app.use(express.json());

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

//  listeners
client.connect()
    .then(() => app.listen(port, () => console.log(`Server listening ${port} and successfully connected with DB.`)))
    .catch((err) => console.log(err))

//  DB & collections
const database = client.db("InfraCare");
const Issues = database.collection("issues");
const User = database.collection("users");

//  Public Api
app.get("/", async (req, res) => res.send("Server is getting!"))
app.get("/issues", async (req, res) => {
    try {
        const result = await Issues.find().toArray()
        res.send(result)
    } catch (error) {
        console.error("DB error: ", error)
        res.status(500).send([])
    }
})

//  Private Api
app.post("/issue", async (req, res) => {
    try {
        const user = await User.findOne({ email: req?.body?.email })
        if (!user) return res.status(403).send({ success: false, message: "Unauthorized Access!" })
        const { title, description, image, location, category } = req.body
        const data = {
            title,
            description,
            image,
            location,
            category,
            citizen: user.email,
            updatedAt: new Date().toISOString(),
            createdAt: new Date().toISOString()
        }
        const result = await Issues.insertOne(data)
        if (!result.acknowledged) res.status(500).send({ success: false, message: "Failed to submit your issue" });
        else res.send({ success: true, message: "Successfully submitted your issue" });
    } catch (error) {
        console.error("DB error: ", error)
        res.status(500).send({ success: false, message: "Internal Server Error!" })
    }
})