const cors = require("cors");
const express = require("express");
const _ = require("loadsh");
const data = require("./users.json");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const offersData = require("./offers.json");
const { v4 } = require("uuid");

const saltRounds = 10;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(
  session({
    key: "userID",
    secret: "verylongword",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60,
    },
  })
);
const verifyJWT = (req, res, next) => {
  const token = req.headers["x-access-token"];
  if (!token) {
    res.send("token is needed");
  } else {
    jwt.verify(token, "verylongsecret", (err, decoded) => {
      if (err) {
        res.json({ auth: false, message: "you failed to authticate" });
      } else {
        req.userID = decoded.id;
        next();
      }
    });
  }
};
app.get("/", (req, res) => {
  fs.readFile("users.json", "utf8", (err, data) => {
    if (err) {
      console.error(err);
      return;
    }

    res.send(data);
  });
});
app.get("/offers", (req, res) => {
  res.send(offersData);
});
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const searchData = data.filter((user) => user.email === email);
  if (searchData.length > 0) {
    bcrypt.compare(password, searchData[0].hashedPassword, (err, response) => {
      if (response) {
        req.session.user = searchData;
        const id = searchData[0].email;
        const token = jwt.sign({ id }, "verylongsecret", { expiresIn: "1h" });

        res.json({
          auth: true,
          token: token,
          result: {
            userName: searchData[0].name,
            userEmail: searchData[0].email,
          },
        });
      } else {
        res.send({ message: "Password is wrong" });
      }
    });
  } else {
    res.send({ message: "User doesn't exist" });
  }
});
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;
  const searchData = data.filter((user) => user.email === email);
  if (searchData.length > 0) {
    res.send({
      userExiset: true,
      message: "Cannot create user,user is already registerd",
    });
  } else {
    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
      if (err) {
        alert(err);
      }
      try {
        fs.writeFile(
          "users.json",
          JSON.stringify([...data, { name, email, hashedPassword }]),
          function (err) {
            if (err) throw err;
            console.log("complete");
          }
        );
      } catch (e) {
        console.log("file couldn't update");
      }
    });
    res.end();
  }
});
app.post("/offers", verifyJWT, (req, res) => {
  try {
    fs.writeFile(
      "offers.json",
      JSON.stringify([...offersData, req.body]),
      function (err) {
        if (err) throw err;
        console.log("complete");
      }
    );
  } catch (e) {
    res.send({
      isAdded: false,
      msg: "there is a problem with adding the file",
    });
  }
  res.send({
    isAdded: true,
    msg: "offer added successfully",
    addedOffer: req.body,
  });
});
app.listen(4000, (err) => {
  if (err) {
    console.log("there was a problem", err);
    return;
  }
  console.log("listeing on port 4000");
});
