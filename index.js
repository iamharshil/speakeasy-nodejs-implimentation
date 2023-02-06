const express = require("express");
const speakeasy = require("speakeasy");
const uuid = require("uuid");
const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");

const app = express();

app.use(express.json());

const db = new JsonDB(new Config("myDatabase", true, false, "/")); // true -> db.push, false -> human readable, / seperator

app.get("/api", (req, res) => {
	res.json({ message: "Welcome to API." });
});

// register user create temp secret
app.post("/api/register", (req, res) => {
	const id = uuid.v4();

	try {
		const path = `/user/${id}`;
		const temp_secret = speakeasy.generateSecret();
		db.push(path, { id, temp_secret });
		res.json({ id, secret: temp_secret.base32 });
	} catch (error) {
		console.log(error);
		res.json({ error: error.message });
	}
});
// we can add data to database directly.

// verify token
app.post("/api/verify", async (req, res) => {
	const { token, userId } = req.body;
	try {
		const path = `/user/${userId}`;
		const user = await db.getData(path);

		const { base32: secret } = user.temp_secret;

		const verified = speakeasy.totp.verify({
			secret,
			encoding: "base32",
			token,
		});

		if (verified) {
			db.push(path, { id: userId, secret: user.temp_secret });
			res.json({ verified: true });
		} else {
			res.json({ verified: false });
		}
	} catch (error) {
		console.log(error);
		res.json({ error: error.message });
	}
});

// validate token
app.post("/api/validate", async (req, res) => {
	const { token, userId } = req.body;
	try {
		const path = `/user/${userId}`;
		const user = await db.getData(path);

		const { base32: secret } = user.secret;

		const tokenValidated = speakeasy.totp.verify({
			secret,
			encoding: "base32",
			token,
			window: 1
		});

		if (tokenValidated) {
			db.push(path, { id: userId, secret: user.secret });
			res.json({ validated: true });
		} else {
			res.json({ validated: false });
		}
	} catch (error) {
		console.log(error);
		res.json({ error: error.message });
	}
});


app.listen(3000, () => console.log("App is running..."));
