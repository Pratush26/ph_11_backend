import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import admin from 'firebase-admin'
import Stripe from "stripe";

dotenv.config();
const app = express();
const port = process.env.PORT || 2000;
const uri = process.env.DB;
const allowedOrigins = process.env.FRONTENDS.split(",");

app.use(cors({
    origin: allowedOrigins ? allowedOrigins : ['http://localhost:5173']
}));
app.use(express.json());

admin.initializeApp({
    credential: admin.credential.cert({
        type: process.env.FB_TYPE,
        project_id: process.env.FB_PROJECT_ID,
        private_key_id: process.env.FB_PRIVATE_KEY_ID,
        private_key: process.env.FB_PRIVATE_KEY.replace(/\\n/g, "\n"),
        client_email: process.env.FB_CLIENT_EMAIL,
        client_id: process.env.FB_CLIENT_ID,
        auth_uri: process.env.FB_AUTH_URI,
        token_uri: process.env.FB_TOKEN_URI,
        auth_provider_x509_cert_url: process.env.FB_AUTH_PROVIDER_X509_CERT_URL,
        client_x509_cert_url: process.env.FB_CLIENT_X509_CERT_URL,
        universe_domain: process.env.FB_UNIVERSE_DOMAIN,
    })
});

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
const Categories = database.collection("categories");
const Transactions = database.collection("transactions");
const Users = database.collection("users");

Categories.createIndex({ name: 1 }, { unique: true })
Transactions.createIndex({ transactionId: 1 }, { unique: true });

//  Middleware
const verifyToken = async (req, res, next) => {
    if (!req.headers?.authorization) return res.status(401).send("Unauthorized Access");
    try {
        const token = req.headers.authorization?.split(" ")[1];
        const decoded = await admin.auth().verifyIdToken(token);
        if (!decoded?.email) return res.status(401).send("Unauthorized Access");
        req.token_email = decoded.email
        next();
    } catch (err) {
        console.error(err);
        res.status(401).send("Unauthorized Access");
    }
}

//  Public Api
app.get("/", async (req, res) => res.send("Server is getting!"))
app.get("/latest-issues", async (req, res) => {
    try {
        const result = await Issues.find().sort({ createdAt: 1 }).limit(6).toArray()
        res.send(result ?? [])
    } catch (error) {
        console.error("DB error: ", error)
        res.status(500).send([])
    }
})
app.get("/categories", async (req, res) => {
    try {
        const result = await Categories.find().toArray()
        res.send(result)
    } catch (error) {
        console.error("DB error: ", error)
        res.status(500).send([])
    }
})

//  Private Api
//  users route
app.get("/userInfo", verifyToken, async (req, res) => {
    const result = await Users.findOne({email: req?.token_email})
    res.send(result ?? {});
})
app.get("/users", async (req, res) => {
    try {
        const { role, limit = 10, skip = 0 } = req.query

        const filter = {}
        if (role) filter.role = role
        const result = await Users.aggregate([
            { $match: filter },

            {
                $lookup: {
                    from: "issues",
                    localField: "_id",
                    foreignField: "submittedBy",
                    as: "issues"
                }
            },
            {
                $addFields: {
                    issueCount: { $size: "$issues" }
                }
            },
            {
                $project: {
                    issues: 0
                }
            },
            { $limit: Number(limit) },
            { $skip: Number(skip) }
        ]).toArray();

        res.send(result ?? [])
    } catch (error) {
        res.status(500).send({ error: "Failed to fetch users" })
    }
})

app.post("/add-staff", verifyToken, async (req, res) => {
    let userRecord;
    try {
        const creator = await Users.findOne({ email: req.token_email }, { projection: { role: 1 } });
        if (!creator || creator.role !== "admin") return res.status(403).send({ success: false, message: "Forbidden!" });

        const { name, email, password, photo, phone, nid, address } = req.body;
        if (!name || !email || !password) return res.status(400).send({ success: false, message: "Missing required fields" });

        let fbUser;
        try {
            fbUser = await admin.auth().getUserByEmail(email);
        } catch (err) {
            if (err.code === "auth/user-not-found") fbUser = null;
            else throw err;
        }

        if (!fbUser) userRecord = await admin.auth().createUser({ email, password, displayName: name, photoURL: photo || null });

        const dbUser = await Users.findOne({ email }, { projection: { email: 1 } });
        if (dbUser) {
            const result = await Users.updateOne(
                { email },
                { $set: { name, phone, photo, role: "staff", nid, address, createdBy: req.token_email, blocked: false } }
            );
            if (!result.modifiedCount) return res.status(500).send({ success: false, message: "Internal Server Error" });
            return res.send({ success: true, message: "Staff updated successfully" });
        } else {
            const result = await Users.insertOne({
                email,
                name,
                phone,
                photo,
                role: "staff",
                nid,
                address,
                createdBy: req.token_email,
                blocked: false,
                premium: false,
                createdAt: new Date().toISOString()
            });
            if (!result.acknowledged) return res.status(500).send({ success: false, message: "Internal Server Error" });
            res.send({ success: true, message: "Staff created successfully" });
        }

    } catch (error) {
        if (userRecord?.uid) await admin.auth().deleteUser(userRecord.uid);
        console.error("Add staff error:", error);
        return res.status(500).send({ success: false, message: "Internal Server Error" });
    }
});

app.post("/citizen", async (req, res) => {
    try {
        const { email, role = "citizen", name, photo } = req.body
        const exists = await Users.findOne({ email })
        if (exists) return res.status(200).send({ success: true, message: "Account already Exists!" })

        const result = await Users.insertOne({ email, role, name, photo, blocked: false, premium: false, createdAt: new Date().toISOString() })
        if (!result.acknowledged) res.status(500).send({ success: false, message: "Failed create citizen account" });
        else res.send({ success: true, message: "Successfully created citizen account" });
    } catch (error) {
        console.error("DB error: ", error)
        res.status(500).send({ success: false, message: "Internal Server Error!" })
    }
})

// Issues api
app.get("/issues", async (req, res) => {
    try {
        let { page = 1, limit = 10, priority, status } = req.query;

        page = Math.max(1, Number(page));
        limit = Math.max(1, Number(limit));

        const filter = {};
        if (priority) filter.priority = priority;
        if (status) filter.status = status;

        const pipeline = [
            { $match: filter },
            {
                $addFields: {
                    priorityOrder: {
                        $cond: [{ $eq: ["$priority", "high"] }, 1, 2]
                    }
                }
            },
            { $sort: { priorityOrder: 1, createdAt: -1 } },
            { $skip: (page - 1) * limit },
            { $limit: limit }
        ];

        const result = await Issues.aggregate(pipeline).toArray();
        res.send(result);
    } catch (err) {
        console.error(err);
        res.status(500).send([]);
    }
});

app.get("/totalIssues", async (req, res) => {
    const result = await Issues.countDocuments()
    res.send(Math.ceil(result / req.query?.limit));
})
app.get("/issue/:id", async (req, res) => {
    try {
        const pipeline = [
            { $match: { _id: new ObjectId(req.params.id) } },
            {
                $lookup: {
                    from: "users",
                    localField: "submittedBy",
                    foreignField: "_id",
                    as: "user"
                }
            },
            { $unwind: { path: "$user", preserveNullAndEmptyArrays: true } }
        ];
        const result = await Issues.aggregate(pipeline).toArray();
        res.send(result[0] || {});
    } catch (err) {
        console.error(err);
        res.status(500).send({});
    }
});
app.get("/my-issues", verifyToken, async (req, res) => {
    try {
        const { status, limit = 10, skip = 0 } = req.query;
        const pipeline = [
            {
                $lookup: {
                    from: "users",
                    localField: "submittedBy",
                    foreignField: "_id",
                    as: "user"
                }
            },
            { $unwind: "$user" },
            { $match: { "user.email": req.token_email } },
        ];

        pipeline.push({ $skip: Number(skip) });
        pipeline.push({ $limit: Number(limit) });
        if (status) pipeline.push({ $filter: { status } });

        const result = await Issues.aggregate(pipeline).toArray();
        res.send(result ?? []);
    } catch (error) {
        console.error("DB error: ", error);
        res.status(500).send([]);
    }
});

app.post("/issue", verifyToken, async (req, res) => {
    try {
        const user = await Users.findOne({ email: req.token_email }, { projection: { _id: 1, premium: 1, blocked: 1 } })
        if (!user?._id) return res.status(401).send({ success: false, message: "Unauthorized Access!" })
        if (user.blocked) return res.status(403).send({ success: false, message: "Forbidden Access!" })
        const totalSubmitted = await Issues.countDocuments({ submittedBy: user._id })
        if (!user.premium && totalSubmitted >= 3) return res.status(406).send({ success: false, message: "Free trier end! Premium subscription required." })

        const { title, description, photo, location, category } = req.body
        const name = category.trim().toLowerCase()
        await Categories.updateOne(
            { name },
            { $setOnInsert: { name } },
            { upsert: true }
        )

        const result = await Issues.insertOne({
            title,
            description,
            photo,
            location,
            category,
            status: "pending",
            assignedTo: "",
            voted: [],
            priority: "low",
            timeline: [],
            submittedBy: user._id,
            updatedAt: new Date().toISOString(),
            createdAt: new Date().toISOString()
        })
        if (!result.acknowledged) return res.status(500).send({ success: false, message: "Failed to submit your issue" });

        res.send({ success: true, message: "Successfully submitted your issue" });
    } catch (error) {
        console.error("DB error: ", error)
        res.status(500).send({ success: false, message: "Internal Server Error!" })
    }
})
app.patch("/upvote", async (req, res) => {
    const userId = new ObjectId(req.body?.id);

    await Issues.updateOne(
        { _id: new ObjectId(req.body?.issueId) },
        [
            {
                $set: {
                    voted: {
                        $cond: [
                            { $in: [userId, "$voted"] },  //  condition
                            { $setDifference: ["$voted", [userId]] }, // remove(true)
                            { $concatArrays: ["$voted", [userId]] }  // add(false)
                        ]
                    }
                }
            }
        ]
    );
    res.send({ success: true });
});

//  payment related route
app.post("/checkout-session", verifyToken, async (req, res) => {
    try {
        const issue = await Issues.findOne({ _id: new ObjectId(req.body?.id) });
        if (!issue) return res.send({ url: "" })
        const origin = req.headers.origin;
        const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
        const session = await stripe.checkout.sessions.create({
            line_items: [
                {
                    price_data: {
                        currency: "BDT",
                        unit_amount: 200 * 100,
                        product_data: {
                            name: issue.title
                        }
                    },
                    quantity: 1,
                },
            ],
            customer_email: req?.token_email,
            metadata: {
                issueId: req.body?.id,
                photo: issue.photo
            },
            mode: 'payment',
            success_url: `${origin}/after-payment?success=true&type=boost&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${origin}/after-payment?success=false&type=boost`,
        });
        res.send({ url: session.url });
    } catch (error) {
        console.error(error)
        res.send({ url: "" })
    }
})
app.patch("/update-paymentStatus", async (req, res) => {
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const session = await stripe.checkout.sessions.retrieve(req.body.session_id);
    if (session.status === "complete") {
        if (req.query.type === "boost") {
            await Issues.updateOne({ _id: new ObjectId(session.metadata.issueId), transactionId: null }, {
                $set: {
                    priority: "high",
                    transactionId: session.payment_intent,
                    updatedAt: new Date().toISOString()
                },
                $push: {
                    state: {
                        title: "Boost priority",
                        description: `Successfully boost issue priority with ${session.currency.toUpperCase()} ${session?.amount_total / 100}`,
                        completed: true,
                        createdAt: new Date().toISOString()
                    }
                },
            })
        }
        else if (req.query?.type === "subscription") {
            await Issues.updateOne({ email: session.customer_email, premium: false }, {
                $set: {
                    premium: true,
                    transactionId: session.payment_intent,
                }
            })
        }
        await Transactions.updateOne(
            { transactionId: session.payment_intent },
            {
                $setOnInsert: {
                    transactionId: session.payment_intent,
                    paidBy: session.customer_email,
                    status: session.status, issue: session.metadata.issueId,
                    amount: session?.amount_total / 100,
                    createdAt: new Date().toISOString()
                }
            },
            { upsert: true }
        );
        if (session.payment_status !== "paid") res.status(402).send({ message: "There is something wrong with your payment process" })
        else res.send({ cost: session.amount_total / 100, currency: session.currency, issueId: session.metadata.issueId })
    }
    else res.status(404).send("Something went wrong!")
})
app.post("/premium-checkout-session", verifyToken, async (req, res) => {
    try {
        const user = await Users.findOne({ _id: new ObjectId(req.token_email), });
        if (user.premium) return res.send({ url: "", message: "You are already a premium subscriber" })
        const origin = req.headers.origin;
        const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
        const session = await stripe.checkout.sessions.create({
            line_items: [
                {
                    price_data: {
                        currency: "BDT",
                        unit_amount: 1000 * 100,
                        product_data: {
                            name: "InfraCare Premium Subscription"
                        }
                    },
                    quantity: 1,
                },
            ],
            customer_email: req?.token_email,
            mode: 'payment',
            success_url: `${origin}/after-payment?success=true&type=subscription&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${origin}/after-payment?success=false&type=subscription`,
        });
        res.send({ url: session.url });
    } catch (error) {
        console.error(error)
        res.send({ url: "" })
    }
})

//  transaction route
app.get("/transactions", async (req, res) => {
    try {
        let { page = 1, limit = 10, email } = req.query;
        const filter = {};

        page = Math.max(1, Number(page));
        limit = Math.max(1, Number(limit));
        if (email) filter.email = email;

        const pipeline = [
            { $match: filter },
            { $skip: (page - 1) * limit },
            { $limit: limit }
        ];
        const result = await Transactions.aggregate(pipeline).toArray();
        res.send(result);
    } catch (err) {
        console.error(err);
        res.status(500).send([]);
    }
});

app.get("/totalTransactions", async (req, res) => {
    const result = await Transactions.countDocuments()
    res.send(Math.ceil(result / req.query?.limit));
})
