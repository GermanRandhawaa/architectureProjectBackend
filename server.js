"use strict";
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY;
const config = require('./config');
const app = express();
const swaggerJSDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

app.use(express.static(__dirname));

app.use(express.json());
app.use(
  cors({
    origin: "http://127.0.0.1:5500",
    credentials: true,
  })
);
app.use(helmet());
app.use(express.urlencoded({ extended: true }));

const connection = mysql.createConnection(process.env.DATABASE_URL);
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Resume Parser App",
      version: "1.0.0",
      description: "Amir LAB",
    },
  },
  apis: ["server.js"], // Add the filename of your Express.js application
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const verifyToken = (req, res, next) => {
  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        res.clearCookie("jwt");
        res.redirect("/login");
      } else {
        req.user = decoded;
        next();
      }
    });
  } else {
    res.redirect("/login");
  }
};

if (connection) {
  console.log(config.db.connected);
}

app.get("/index", verifyToken, (req, res) => {
  res.send("$$$$");
});

const userApiCallCounts = {};

/**
 * @swagger
 * /login:
 *   post:
 *     summary: User login endpoint
 *     description: Authenticates a user and returns a JWT token
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             example:
 *               message: Login successful
 *               role: user
 *               apiCallCount: 1
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid credentials
 */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const token = req.cookies && req.cookies.jwt;
    if (token) {
      try {
        const decoded = jwt.verify(token, secretKey);
        console.log(decoded);
      } catch (err) {
        console.log(err);
      }
    } else {
      console.log(config.token);
    }
  } catch (error) {
    console.error("Error:", error);
  }

  const query = "SELECT * FROM users WHERE username = ?";
  connection.query(query, [username], async (error, results) => {
    if (error) {
      console.error(config.db.err, error);
      res.status(500).json({ message: config.db.err });
    } else {
      // Increment the API call count for the specific user
      userApiCallCounts[username] = (userApiCallCounts[username] || 0) + 1;

      console.log(`${username} API Call Count:`, userApiCallCounts[username]); // Log the API call count

      if (results.length > 0) {
        const { password: hashedPassword, role } = results[0];
        const match = await bcrypt.compare(password, hashedPassword);
        if (match) {
          // Update the api_calls column in the calls table
          const updateQuery =
            "INSERT INTO calls (username, api_calls) VALUES (?, 1) ON DUPLICATE KEY UPDATE api_calls = api_calls + 1";
          connection.query(updateQuery, [username], (updateError) => {
            if (updateError) {
              console.error("Error updating api_calls:", updateError);
              res.status(500).json({ message: config.api });
            } else {
              const token = jwt.sign({ username, role }, secretKey, {
                expiresIn: "1h",
              });

              res.cookie("jwt", token, {
                httpOnly: true,
                maxAge: 3600000, // 1 hour
                sameSite: "strict",
              });

              // Send the user's role along with the successful login message
              res.json({
                message: config.db.login,
                role,
                apiCallCount: userApiCallCounts[username],
              });
            }
          });
          connection.query(
            "SELECT * FROM epcounter WHERE username = ?",
            [username],
            (error, results) => {
              if (error) {
                console.error(config.db.username, error);
                res.status(500).json({ error: config.server });
              } else if (results.length === 0) {
                // Username not found, initialize with a value of 1
                connection.query(
                  "INSERT INTO epcounter (username, descAnalysis, resumeFeedback, jobFeedback, calls, login, userinfos, deleteCount) VALUES (?, 0, 0, 0, 0, 1, 0, 0);",
                  [username],
                  (insertError) => {
                    if (insertError) {
                      console.error(
                        config.db.username,
                        insertError
                      );
                    } 
                  }
                );
              }else{
                login_counter(username)
              }
            }
          );
        } else {
          res.status(401).json({ message: config.db.credentials });
        }
      } else {
        res.status(401).json({ message: config.db.credentials });
      }
    }
  });
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: User registration endpoint
 *     description: Registers a new user and returns a success message
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             example:
 *               message: User registered successfully
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               message: Error registering user
 *               error: <error_message>
 */
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertQuery =
      "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
    connection.query(
      insertQuery,
      [username, email, hashedPassword, "user"],
      (error, results) => {
        if (error) {
          console.error(config.db.register_err, error);
          res
            .status(500)
            .json({ message: config.db.register_err, error: error.message });
        } else {
          res.status(201).json({ message: config.db.register });
        }
      }
    );
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: config.db.register_err });
  }
});

const getAllUserInfos = (req, res) => {
  const query = "SELECT username, email FROM users";
  connection.query(query, (error, results) => {
    if (error) {
      console.error("Error querying user information:", error);
      res.status(500).json({ message: "Error querying user information" });
    } else {
      // Send user information as a JSON response
      res.json(results);
    }
  });
};

const getAllUserCalls = (req, res) => {
  const query = "SELECT * FROM calls";
  connection.query(query, (error, results) => {
    if (error) {
      console.error(config.user_info, error);
      res.status(500).json({ message: config.user_info });
    } else {
      // Send user information as a JSON response
      res.json(results);
    }
  });
};

const getAllUserEp = (req, res) => {
  const query = "SELECT * FROM epcounter";
  connection.query(query, (error, results) => {
    if (error) {
      console.error(config.user_info, error);
      res.status(500).json({ message: config.user_info });
    } else {
      // Send user information as a JSON response
      res.json(results);
    }
  });
};

/**
 * @swagger
 * /get-all-users:
 *   get:
 *     summary: Get all user information
 *     description: Retrieves information about all registered users
 *     tags:
 *       - Users
 *     responses:
 *       200:
 *         description: Successful retrieval of user information
 *         content:
 *           application/json:
 *             example:
 *               - username: user1
 *                 email: user1@example.com
 *               - username: user2
 *                 email: user2@example.com
 *               # ... (more users)
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               message: Error querying user information
 */
app.get("/get-all-users", getAllUserInfos);

/**
 * @swagger
 * /get-calls:
 *   get:
 *     summary: Get all user API call information
 *     description: Retrieves information about API calls made by users
 *     tags:
 *       - Users
 *     responses:
 *       200:
 *         description: Successful retrieval of user API call information
 *         content:
 *           application/json:
 *             example:
 *               - username: user1
 *                 api_calls: 10
 *               - username: user2
 *                 api_calls: 5
 *               # ... (more users)
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               message: Error querying user information
 */
app.get("/get-calls", getAllUserCalls);

/**
 * @swagger
 * /get-ep:
 *   get:
 *     summary: Get all user endpoint information
 *     description: Retrieves information about user endpoints
 *     tags:
 *       - Users
 *     responses:
 *       200:
 *         description: Successful retrieval of user endpoint information
 *         content:
 *           application/json:
 *             example:
 *               - username: user1
 *                 descAnalysis: 5
 *                 resumeFeedback: 3
 *                 jobFeedback: 2
 *                 calls: 10
 *                 login: 5
 *                 userinfos: 8
 *                 deleteCount: 1
 *               - username: user2
 *                 descAnalysis: 2
 *                 resumeFeedback: 1
 *                 jobFeedback: 0
 *                 calls: 5
 *                 login: 2
 *                 userinfos: 3
 *                 deleteCount: 0
 *               # ... (more users)
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               message: Error querying user information
 */
app.get("/get-ep", getAllUserEp);

const deleteUser = (req, res) => {
  const { username } = req.params;

  // Delete the user from the database
  const deleteQuery = "DELETE FROM users WHERE username = ?";
  connection.query(deleteQuery, [username], (error, results) => {
    if (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ message: "Error deleting user" });
    } else {
      // Check if the user was found and deleted
      if (results.affectedRows > 0) {
        console.log(`User ${username} deleted successfully`);
        del()
        res.json({ message: `User ${username} deleted successfully` });
      } else {
        res.status(404).json({ message: `User ${username} not found` });
      }
    }
  });
};

/**
 * @swagger
 * /users/{username}:
 *   delete:
 *     summary: Delete a user
 *     description: Deletes a user based on the provided username
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: The username of the user to be deleted
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User deleted successfully
 *         content:
 *           application/json:
 *             example:
 *               message: User deleted successfully
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: User not found
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               message: Error deleting user
 */
app.delete("/users/:username", deleteUser);


/**
 * @swagger
 * /incrementCount/{username}:
 *   patch:
 *     summary: Increment API call count for a user
 *     description: Increments the API call count for the specified user
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: The username for which to increment the API call count
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: API call count incremented successfully
 *         content:
 *           application/json:
 *             example:
 *               count: 6
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               message: Error updating API call count
 */
app.patch("/incrementCount/:username", async (req, res) => {
  const { username } = req.params;
  const countQuery = "SELECT api_calls FROM calls WHERE username = ?";
  let count = 0;
  connection.query(countQuery, [username], (error, results) => {
    if (error) {
      console.error(config.db.err, error);
      res.status(500).json({ message: config.db.err });
    } else {
      count = results[0];
      res.json({ count });
    }
  });
  const updateQuery = "UPDATE calls SET api_calls = ? WHERE username = ?";
  connection.query(updateQuery, [count + 1, username], (error) => {
    if (error) {
      console.error(config.db.err, error);
    }
  });
});

/**
 * @swagger
 * /apiCallCount/{username}:
 *   get:
 *     summary: Get API call count for a user
 *     description: Retrieves the API call count for the specified user
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: The username for which to retrieve the API call count
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Successful retrieval of API call count
 *         content:
 *           application/json:
 *             example:
 *               count: 5
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               message: Error querying API call count
 */
app.get("/apiCallCount/:username", (req, res) => {
  const { username } = req.params;
  const countQuery = "SELECT api_calls FROM calls WHERE username = ?";
  connection.query(countQuery, [username], (error, results) => {
    if (error) {
      console.error(config.db.err, error);
      res.status(500).json({ message: config.db.err });
    } else {
      console.log("counts fetched");
      calls_counter(username);
      const count = results[0];
      res.json({ count: count });

    }
  });
});

/**
 * @swagger
 * /description-analysis/{username}:
 *   patch:
 *     summary: Increment description analysis count for a user
 *     description: Increments the description analysis count for the specified user
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: The username for which to increment the description analysis count
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Description analysis count incremented successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Column updated successfully
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               error: Error updating description analysis count
 */
app.patch("/description-analysis/:username", (req, res) => {
  const { username } = req.params;
  const updateQuery =
    "UPDATE epcounter SET descAnalysis = IFNULL(descAnalysis, 0) + 1 WHERE username = ?";

  connection.query(updateQuery, [username], (updateError) => {
    if (updateError) {
      console.error(config.description, updateError);
      res.status(500).json({ error: config.description });
    } else {
      res.json({ message: config.updateSuccess });
    }
  });
});

app.patch("/resume-feedback/:username", (req, res) => {
  const { username } = req.params;
  const updateQuery =
    "UPDATE epcounter SET resumeFeedback = IFNULL(resumeFeedback, 0) + 1 WHERE username = ?";

  connection.query(updateQuery, [username], (updateError) => {
    if (updateError) {
      console.error(config["resume-feedback"], updateError);
      res.status(500).json({ error: config["resume-feedback"] });
    } else {
      res.json({ message: config.updateSuccess });
    }
  });
});

app.patch("/job-feedback/:username", (req, res) => {
  const { username } = req.params;
  const updateQuery =
    "UPDATE epcounter SET jobFeedback = IFNULL(jobFeedback, 0) + 1 WHERE username = ?";

  connection.query(updateQuery, [username], (updateError) => {
    if (updateError) {
      console.error(config["job-feedback"], updateError);
      res.status(500).json({ error: config["job-feedback"] });
    } else {
      res.json({ message: config.updateSuccess });
    }
  });
});

function calls_counter(username){
  const updateQuery =
    "UPDATE epcounter SET calls = IFNULL(calls, 0) + 1 WHERE username = ?";

  connection.query(updateQuery, [username], (updateError) => {
    if (updateError) {
      console.error(config.calls_counter, updateError);
    } 
  });
};

function login_counter(username) {
  const updateQuery =
    "UPDATE epcounter SET login = IFNULL(login, 0) + 1 WHERE username = ?";

  connection.query(updateQuery, [username], (updateError) => {
    if (updateError) {
      console.error(config.login_counter, updateError);
    } 
  });
};

/**
 * @swagger
 * /userinfos/{username}:
 *   patch:
 *     summary: Increment userinfos count for a user
 *     description: Increments the userinfos count for the specified user
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: The username for which to increment the userinfos count
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Userinfos count incremented successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Column updated successfully
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example:
 *               error: Error updating userinfos count
 */
app.patch("/userinfos/:username", (req, res) => {
  const { username } = req.params;
  const updateQuery =
    "UPDATE epcounter SET userinfos = IFNULL(userinfos, 0) + 1 WHERE username = ?";

  connection.query(updateQuery, [username], (updateError) => {
    if (updateError) {
      console.error(config.userinfos, updateError);
      res.status(500).json({ error: config.userinfos });
    } else {
      res.json({ message: config.updateSuccess });
    }
  });
})

function del() {
  const updateQuery =
    "UPDATE epcounter SET deleteCount = IFNULL(deleteCount, 0) + 1 WHERE username = pahul";

  connection.query(updateQuery, (updateError) => {
    if (updateError) {
      console.error(config.delCounter, updateError);
    } 
  });
}

app.listen(port, () => {
  console.log(config.listen + " " + port);
});

module.exports = app;
