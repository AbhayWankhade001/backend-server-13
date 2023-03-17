
import nodemailer from "nodemailer";
import jwt from 'jsonwebtoken';
import config from './config.js';

import { Router } from "express";
import cryptoRandomString from "crypto-random-string";
const router = Router();
import mongoose, {ObjectId} from "mongoose";

import * as controller from '../controllers/appController.js';
import { registerMail } from '../controllers/mailer.js'

import bcrypt from "bcrypt";
import { User, Form, Employee, Admin, OTP, EmployeeSchema } from '../model/User.model.js';
import pkg from 'node-sessionstorage';
const { sessionStorage } = pkg;
import generateToken, { verifyToken } from "../middleware/auth.js"

/** POST Methods */
// router.post('/register', async (req, res) => {
//     const { username, password, email, firstName, lastName, phoneNumber, address } = req.body;

//     // Check if user with the same username or email already exists
//     const existingUser = await UserModel.findOne({ $or: [{ username }, { email }] });
//     if (existingUser) {
//       return res.status(400).send({ message: 'User already exists' });
//     }

//     // Save the new user to the database
//     const newUser = new UserModel({ username, password, email, firstName, lastName, phoneNumber, address });
//     await newUser.save();

//     // Send a response back to the client
//     res.send({ message: 'User registered successfully' });
//   });
const jwt_Secret = config.JWT_SECRET;




// router.route('/registerMail').post(registerMail); // send the email
// router.route('/authenticate').post(controller.verifyUser, (req, res) => res.end()); // authenticate user
// // router.route('/login').post(controller.login); // login in app
// router.route('/procted').post(generateToken);
// /** GET Methods */
// router.route('/user/:username').get(controller.getUser) // user with username
// // router.route('/generateOTP').get(controller.verifyUser, localVariables, controller.generateOTP) // generate random OTP
// router.route('/verifyOTP').get(controller.verifyUser, controller.verifyOTP) // verify generated OTP
// router.route('/createResetSession').get(controller.createResetSession) // reset all the variables
// router.route('/register').get(controller.getCollectionData); // register user




const secretKey = config.JWT_SECRET;


router.get('/user-data', async (req, res) => {
  try {
    // Get the JWT token from the client's local storage
    const token = req.headers.authorization.split(' ')[1] || localStorage.getItem('token');
    if (!token) {
      return res.status(401).send({ message: 'Invalid or missing JWT token' });
    }

    // Verify the JWT token and get the user's ID
    const decodedToken = jwt.verify(token, config.JWT_SECRET);
    const userId = decodedToken.userId;

    // Get the user's username from the database
    const user = await UserModel.findById(userId).select('username');
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }

    // Send the user's username back to the client
    res.send({ username: user.username });
  } catch (error) {
    res.status(401).send({ message: 'Invalid or missing JWT token' });
  }
});

router.get('/protected', (req, res) => {
  try {
    // Get JWT token from request headers
    const token = req.headers.authorization.split(' ')[1];

    // Verify JWT token with secret key
    const decodedToken = jwt.verify(token, 'jwt_Secret');

    // Get user ID from decoded token
    const userId = decodedToken.userId;

    // Send response with user ID
    res.send(`User ID: ${userId}`);
  } catch (error) {
    // Send error response if token is invalid or missing
    res.status(401).send('Invalid or missing JWT token');
  }
});

/** PUT Methods */
// router.route('/updateuser').put(Auth, controller.updateUser); // is use to update the user profile
router.route('/resetPassword').put(controller.verifyUser, controller.resetPassword); // use to reset password







// Register endpoint
router.post('/register', async (req, res) => {
  console.log("New user registration request received");

  // Check required fields
  if (!req.body.username || !req.body.password || !req.body.email) {
    console.log("Required fields missing");
    return res.status(400).send("Username, password, and email are required fields");
  }

  // Check if user already exists
  const existingUser = await User.findOne({ username: req.body.username });
  if (existingUser) {
    console.log("Username already exists");
    return res.status(409).send("Username already exists");
  }

  // Encrypt password using bcrypt
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  // Create new user object with form data
  const newUser = new User({
    username: req.body.username,
    password: hashedPassword,
    email: req.body.email,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    phoneNumber: req.body.phoneNumber,
    address: req.body.address
  });

  // Save new user object to database
  try {
    const savedUser = await newUser.save();
    console.log("New user saved to database");

    // Generate JWT token
    const token = jwt.sign({ _id: savedUser._id }, config.JWT_SECRET);
    console.log("JWT token generated for user:", savedUser.username);

    // Store token in cookie
    res.cookie('auth-token', token, {
      maxAge: 86400000, // 24 hours
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    });

    res.send({ message: 'Registration successful' });
  } catch (err) {
    console.log("Error saving user to database:", err.message);
    res.status(500).send("email already exist ");
  }
});






function getTokenFromCookies(req) {

  if (!req) {
    console.log("Request is undefined or null");
    return null;
  }

  let token = req.headers['authorization'] || req.cookies['token'];
  if (!token) {
    console.log("No token found in cookies");
    return null;
  }

  try {
    // Remove "Bearer " prefix if present
    if (token.startsWith("Bearer ")) {
      token = token.slice(7, token.length);
    }
    const decodedToken = jwt.verify(token, config.JWT_SECRET);
    console.log("Decoded token:", decodedToken);

    // Check if decoded token contains required fields (e.g. user ID)
    if (!decodedToken.userId || !decodedToken.email) {
      console.log("Invalid token. Missing required fields");
      return null;
    }

    return decodedToken; // Return decoded token object
  } catch (err) {
    console.log("Error decoding token:", err.message);
    return null;
  }
}

const authorize = (req, res, next) => {
  const authToken = getTokenFromCookies(req); // Use authToken to decode
  if (!authToken) {
    console.log("No authorization token provided");
    return res.status(401).send("Access denied. No token provided");
  }

  try {
    req.user = {
      id: authToken.userId,
      email: authToken.email,
    };
    next();
  } catch (err) {
    console.log("Invalid authorization token provided");
    res.status(400).send("Invalid token provided");
  }
};

router.post('/addData', authorize, async (req, res) => {
  console.log("User data add request received");

  // Get user ID from token
  const userId = req.user.id;
  if (!userId) {
    return res.status(401).send("Unauthorized");
  }

  try {
    // Find the existing user object in database
    let user = await User.findById(userId);
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ error: "User not found" });
    }

    // Update the user object with new form data
    if (!user.form) {
      user.form = {}; // Create a new form object if it doesn't exist
    }
    if (req.body.accountholdername) user.form.accountholdername = req.body.accountholdername;
    if (req.body.mobilenumber) user.form.mobilenumber = req.body.mobilenumber;
    if (req.body.acctype) user.form.acctype = req.body.acctype;
    if (req.body.bankname) user.form.bankname = req.body.bankname;
    if (req.body.branchname) user.form.branchname = req.body.branchname;
    if (req.body.ifsc) user.form.ifsc = req.body.ifsc;
    if (req.body.branchname) user.form.branchname = req.body.branchname;
    if (req.body.pannumber) user.form.pannumber = req.body.pannumber;

    // Save the updated user object to the database
    user = await user.save();
    console.log("User data added/updated successfully. User ID:", userId, "Form data:", user.form);
    res.send(user);
  } catch (err) {
    console.log("Error adding/updating user data:", err.message);
    res.status(500).json({ error: "Error adding/updating user data" });
  }
});


router.get('/users2', (req, res) => {
  res.status(201).json("its working finilla😍😍😍😍")
})


//working api don't remove it  all are working below

router.get('/userData', authorize, async (req, res) => {
  console.log("User data fetch request received");

  // Get user ID from token
  const userId = req.user.id;
  if (!userId) {
    return res.status(401).send("Unauthorized");
  }

  try {
    // Find the existing user object in database
    let user = await User.findById(userId);
    console.log("User object:", user);
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ error: "User form not found" });
    }

    // Return the user's form data
    res.send(user);
    // res.send(user.form);
  } catch (err) {
    console.log("Error fetching user data:", err.message);
    res.status(500).json({ error: "Error fetching user data" });
  }
});



const otpStore = {};

// Define route handler for admin registration
router.post('/admin/register', async (req, res) => {
  const { email, password } = req.body;

  // Generate OTP and save it in the temporary store along with email and hashed password
  const otp = cryptoRandomString({ length: 6, type: 'numeric' });
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  otpStore[email] = { otp, email, hashedPassword };

  // Send OTP to the admin's email address
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'surendrawankhade1973@gmail.com',
      pass: 'cyjepyhwchonjuii',
    },
  });
  const mailOptions = {
    from: 'surendrawankhade1973@gmail.com',
    to: email,
    subject: 'OTP for email verification',
    text: `Your OTP for admin registration is ${otp}.`,
  };
  await transporter.sendMail(mailOptions);

  res.send('OTP sent to your email address.');
});

// Define route handler for verifying OTP and creating admin account
router.post('/admin/register/verify', async (req, res) => {
  const { email, otp,password } = req.body;

  // Check if OTP matches the one in the temporary store
  if (!otpStore[email] || otpStore[email].otp !== otp) {
    return res.status(400).send('Invalid OTP.');
  }

  // Check if password field is present
  if (!password) {
    return res.status(400).send('Password field is required.');
  }

  // Hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create a new admin user in the database
  const admin = new Admin({ email, password: hashedPassword });
  try {
    await admin.save();
  } catch (error) {
    if (error.code === 11000 && error.keyPattern.email === 1) {
      return res.status(400).send('Email is already registered.');
    }
    throw error; // re-throw the error if it's not a duplicate key error
  }

  // Delete the OTP from the temporary store
  delete otpStore[email];

  // Generate a JWT token and store it in cookies
  const token = jwt.sign({  email, adminId: admin._id  }, config.JWT_SECRET);
  res.cookie('token', token);

  console.log('Token:', token); // Debugging purposes only

  res.send('Admin account created successfully.');
});

// Define route handler for verifying token and saving admin to database
router.post('/admin/verify', async (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).send('Unauthorized.');
  }

  try {
    const { email } = jwt.verify(token, config.JWT_SECRET);

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).send('Admin not found.');
    }

    // Save the admin to the database
    // ...

    res.send('Admin saved to database.');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error.');
  }
});


router.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if admin credentials are valid
  const admin = await Admin.findOne({ email });
  if (!admin) {
    return res.status(401).send('Invalid email or password.');
  }

  const isPasswordMatch = await bcrypt.compare(password, admin.password);
  if (!isPasswordMatch) {
    return res.status(401).send('Invalid email or password.');
  }

  // Generate a JWT token and store it in cookies
  const token = jwt.sign({ email, adminId: admin._id }, config.JWT_SECRET);
  res.cookie('token', token);

  console.log('Token:', token); // Debugging purposes only

  res.send('Admin logged in successfully.');
});


function checkRequiredFields(obj, fields) {
  return fields.every(field => Object.prototype.hasOwnProperty.call(obj, field) && obj[field]);
}


  // Send login details to employee email
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'surendrawankhade1973@gmail.com',
      pass: 'cyjepyhwchonjuii',
    }
  });
  router.post('/createEmployees', async (req, res) => {
    try {
      const authorizationHeader = req.headers.authorization;
      if (!authorizationHeader) {
        throw new Error('Authorization header is missing');
      }
      
      const { firstName, lastName, email, password } = req.body;
      if (!checkRequiredFields(req.body, ['firstName', 'lastName', 'email', 'password'])) {
        throw new Error('firstName, lastName, email, and password are required');
      }
  
      // Generate password hash using bcrypt
      const passwordHash = await bcrypt.hash(password, 10);
  
      const token = authorizationHeader.split(' ')[1];
      const tokenData = jwt.verify(token, config.JWT_SECRET);
      const adminId = tokenData.adminId;
  
      console.log('Admin ID:', adminId);
      console.log('Started creating new employee');
      console.log('authorizationHeader:', authorizationHeader);
      console.log('token:', token);
      console.log('tokenData:', tokenData);
      console.log('adminId:', adminId);
  
      const admin = await Admin.findById(adminId);
      if (!admin) {
        throw new Error('Admin not found');
      }
      console.log('Admin:', admin);
  
      const employee = new Employee({
        firstName,
        lastName,
        email,
        password: passwordHash,
        admin: adminId,
      });
  
      await employee.save();
      console.log('New employee created:', employee);
  
      // Send login details to employee's email using NodeMailer
      const mailOptions = {
        from: "surendrawankhade1973@gmail.com",
        to: email,
        subject: 'Congratulations! Your login details for Cling Multi Solution',
        html: `<p>Hello ${firstName},</p>
               <p>Congratulations on being added as an employee of Cling Multi Solution. Here are your login details:</p>
               <p>Email: ${email}</p>
               <p>Password: ${password}</p>
               <p>Please login to your account and reset your password for security reasons.</p>
               <p>Thank you for joining our team!</p>`
      };
    
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log('Error:', error.message);
        } else {
          console.log('Email sent:', info.response);
        }
      });
  
      res.send({ message: 'Employee created successfully' });
      
    } catch (err) {
      console.log('Error:', err.message);
      res.status(400).send({ message: err.message });
    }
  });
  


router.get('/employees', async (req, res) => {
  try {
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
      throw new Error('Authorization header is missing');
    }

    const token = authorizationHeader.split(' ')[1];
    const tokenData = jwt.verify(token, config.JWT_SECRET);
    const adminId = tokenData.adminId;

    const admin = await Admin.findById(adminId);
    if (!admin) {
      throw new Error('Admin not found');
    }

    const employees = await Employee.find({ admin: adminId });
    console.log('Employees:', employees);

    res.send(employees);
  } catch (err) {
    console.log('Error:', err.message);
    res.status(400).send({ message: err.message });
  }
});






router.post('/employeesLogin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!checkRequiredFields(req.body, ['email', 'password'])) {
      throw new Error('Email and password are required');
    }

    const employee = await Employee.findOne({ email });
    if (!employee) {
      throw new Error('Invalid email or password');
    }

    const passwordMatch = await bcrypt.compare(password, employee.password);
    if (!passwordMatch) {
      throw new Error('Invalid email or password');
    }

    const token = jwt.sign(
      { employeeId: employee._id, adminId: employee.admin },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );
    


    res.send({ token });
  } catch (err) {
    console.log('Error:', err.message);
    res.status(400).send({ message: err.message });
  }
});





export default router;
