const express = require('express');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Users } = require('./users');
const { userToken } = require('./userToken');
// const {mongo}
require("./db/conn").config
require("dotenv").config();

const app = express();
const port = 3000;

// Replace with your Zoho Sprints credentials
const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const redirectUri = process.env.REDIRECT_URI;

app.get('/', (req, res) => {
  const authUrl = `${authorizationUrl}?response_type=code&client_id=${clientId}&scope=ZohoProjects.portals.READ,ZohoProjects.projects.UPDATE,ZohoProjects.projects.READ,ZohoProjects.projects.DELETE,ZohoProjects.tasks.ALL,ZohoProjects.projects.CREATE,ZohoProjects.portals.READ&redirect_uri=${redirectUri}&access_type=offline&prompt=consent`;
  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const authCode = req.query.code;

  if (!authCode) {
    return res.status(400).send('Authorization code is missing.');
  }

  try {
    const response = await axios.post(tokenUrl, null, {
      params: {
        code: authCode,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const { access_token, refresh_token } = response.data;

    if (!access_token || !refresh_token) {
      throw new Error('Access token or refresh token not found in the response');
    }

    res.send(`
      <h1>Access Token Obtained Successfully</h1>
      <p><strong>Access Token:</strong> ${access_token}</p>
      <p><strong>Refresh Token:</strong> ${refresh_token}</p>
    `);
  } catch (error) {
    console.error('Error obtaining access token:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/generate-invoice', async (req, res) => {
  const accessToken = 'access_token';
  const organizationId = 'YOUR_ORGANIZATION_ID';

  const invoiceData = {
    customer_id: 'CUSTOMER_ID',
    line_items: [
      {
        item_id: 'ITEM_ID',
        quantity: 1,
        rate: 100,
      },
    ],
    payment_terms: 15,
    payment_terms_label: 'Net 15',
    due_date: '2024-06-15',
  };

  try {
    const response = await axios.post(`https://books.zoho.com/api/v3/invoices?organization_id=${organizationId}`, invoiceData, {
      headers: {
        Authorization: `Zoho-oauthtoken ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    console.log('Invoice created successfully:', response.data);
  } catch (error) {
    console.error('Error creating invoice:', error.response ? error.response.data : error.message);
  }
})

app.get('/get-invoices', async (req, res) => {
  const accessToken = 'access_token';
  const organizationId = 'YOUR_ORGANIZATION_ID';

  try {
    const response = await axios.get(`https://books.zoho.com/api/v3/invoices`, {
      headers: {
        Authorization: `Zoho-oauthtoken ${accessToken}`,
        'Content-Type': 'application/json',
      },
      params: {
        organization_id: organizationId,
      },
    });

    console.log('Invoices retrieved successfully:', response.data);
  } catch (error) {
    console.error('Error retrieving invoices:', error.response ? error.response.data : error.message);
  }
})

app.get('/get-particular-invoice', async (req, res) => {
  const accessToken = 'access_token';
  const organizationId = 'YOUR_ORGANIZATION_ID';
  const invoiceId = 'invoiceId'

  try {
    const response = await axios.get(`https://books.zoho.com/api/v3/invoices/${invoiceId}`, {
      headers: {
        Authorization: `Zoho-oauthtoken ${accessToken}`,
        'Content-Type': 'application/json',
      },
      params: {
        organization_id: organizationId,
      },
    });

    console.log('Invoice retrieved successfully:', response.data);
  } catch (error) {
    console.error('Error retrieving invoice:', error.response ? error.response.data : error.message);
  }
})

// Register User
app.post('/register', async (req, res) => {
  try {
    const existingUser = await Users.findOne({ email_id: req.body.email_id }).exec();
    if (existingUser) {
      return res.status(401).json({
        message: "Email ID already exists",
        data: undefined
      });
    }

    // Hash the password
    bcrypt.hash(req.body.password, 2, async (err, hash) => {
      if (err) {
        return res.status(500).json({
          message: "Error, cannot encrypt password",
          data: undefined
        });
      }

      // Create a new user
      const newUser = new Users({
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        mobile: req.body.mobile,
        email_id: req.body.email_id,
        password: hash
      });

      // Save the user
      await newUser.save();

      // Generate a token for the user
      const token = jwt.sign(
        {
          email_id: newUser.email_id,
          userId: newUser._id
        },
        process.env.JWT_KEY,
        {
          expiresIn: "24h"
        }
      );
      // Save the token in userToken collection
      await userToken.create({ _userId: newUser._id, tokenType: "login", token });

      return res.status(200).json({
        message: "User Registered Successfully",
        data: {
          token,
          user: newUser
        }
      });
    });
  } catch (error) {
    return res.status(500).json({
      message: "Server error, registration failed",
      data: undefined
    });
  }
}),

  //Admin Login
  app.post('/login', async (req, res, next) => {
    Users.findOne({ email_id: req.body.email_id }).exec()
      .then((user) => {
        if (!user) {
          return res.status(401).json({
            message: "User not found",
            data: undefined
          })
        }
        bcrypt.compare(req.body.password, user.password, async (err, result) => {
          if (err) {
            return res.status(401).json({
              message: "Server error, authentication failed",
              data: undefined
            })
          }
          if (result) {
            const token = jwt.sign(
              {
                email_id: user.email_id,
                userId: user._id
              },
              process.env.JWT_KEY,
              {
                expiresIn: "24h"
              }
            );

            await userToken.findOneAndUpdate({ _userId: user._id, tokenType: "login" }, { token: token }, { new: true, upsert: true })
            return res.status(200).json({
              message: "Login successfully!",
              data: {
                token,
                user
              }
            })

          }
          return res.status(401).json({
            message: "Wrong password, login failed",
            data: undefined
          })
        })
      })
      .catch((err) => {
        res.status(500).json({
          message: "Server error, authentication failed",
          data: undefined
        })
      })
  }),



  app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
  });
