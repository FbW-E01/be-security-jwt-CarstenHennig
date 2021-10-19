import express from "express";
import { check, validationResult } from "express-validator";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import bcrypt from "bcrypt";

const users = [
  { username: "Carsten", password: "swordfish" },
  { username: "John", password: "pass123" },
];
console.log(users);

// Setup Express application
const app = express();
app.use(express.json());

// This makes a very secure random secret with every app reboot
const secret = crypto.randomBytes(64).toString("hex");
console.log({ secret });

// This middleware can be used to check if a reqest contains a valid token
function checkTokenMiddleware(req, res, next) {
  const tokenRaw = req.headers.authorization;
  console.log(`Token raw is: "${tokenRaw}""`);
  if (!tokenRaw) {
    return res.sendStatus(401);
  }

  const tokenToCheck = tokenRaw.split(" ")[1];
  console.log(`Token to check is: "${tokenToCheck}"`);
  if (!tokenToCheck) {
    return res.sendStatus(401);
  }

  jwt.verify(tokenToCheck, secret, (error, payload) => {
    console.log({ error, payload });

    if (error) {
      return res.status(400).send(error.message);
    }

    req.userData = {
      userId: payload.userId,
      username: payload.username,
      admin: payload.admin,
    };
    next();
  });
}

// Checking username if unique
const options = [
  check("username")
    .isAlpha()
    .notEmpty()
    .withMessage(
      "The user name should contain only letters and should be unique."
    ),
];

// New user registration

async function hash(password) {
  return await bcrypt.hash(password, 3);
}

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (users.find((x) => x.username === username)) {
    res.status(400).send("username already in use");
  }
  users.push({ username, password: await hash(password) });

  res.send("registration complete, welcome aboard");
});

// This endpoint returns a fresh token
app.post("/login", (req, res) => {
  // TODO: Check login username / password somehow
  const payload = req.body;
  console.log(payload);
  const options = { expiresIn: "5m" };
  const token = jwt.sign(payload, secret, options);
  res.send(token);
});

// This endpoint is secured; only requests with a valid token can access ot
app.get("/login", checkTokenMiddleware, (req, res) => {
  // check token and return something
  res.json(users.filter((x) => x.username === req.userData.username));
  // users.map((x) => {
  // console.log("#1", x.username);
  // console.log("#2", req.userData.username);
  //   if (x.username === req.userData.username) {
  //     return res.send(`Hooray, ${req.userData.username}, you have access`);
  //   }
  //   res.send("No user like that");
  // });
});

const port = 8000;
app.listen(port, () => {
  console.log("Listening on http://localhost:" + port);
});
