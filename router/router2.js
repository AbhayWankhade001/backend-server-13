import express from "express";
import { loginUser, verifyToken } from "../middleware/auth.js";
import User,{Employee , Admin} from "../model/User.model.js";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import config from "./config.js";
import jwt from 'jsonwebtoken';
import { BankDetails } from "../model/User.model.js";
import authorize from "../middleware/auth.js"
const router2 = express.Router();

// Login endpoint
router2.post("/login2", async (req, res) => {
  try {
    await loginUser(req, res);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected endpoint
router2.get("/protected", verifyToken, (req, res) => {
  // req.user and req.token are added by verifyToken middleware
  res.json({ message: "Hello, " + req.user.name });
});
// router2.get('/employees2', async (req, res) => {
//   try {
//     // Get the JWT from the Authorization header and extract the user ID and role
//     const token = req.headers.authorization.split(' ')[1];
//     const decodedToken = jwt.verify(token, config.JWT_SECRET);
//     const userId = decodedToken.userId;
//     const userRole = decodedToken.role;

//     if (userRole !== 'admin') {
//       return res.status(401).json({
//         success: false,
//         message: 'Unauthorized access'
//       });
//     }

//     // Retrieve all employee data associated with the admin ID
//     const employees = await Employee.find({ adminId: userId });

//     // Return the employee data
//     res.status(200).json({
//       success: true,
//       employees: employees
//     });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({
//       success: false,
//       message: 'Internal server error'
//     });
//   }
// });



router2.post("/addBankDetails", async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.verify(token, config.JWT_SECRET);
    const employeeId = decodedToken.employeeId;
    const adminId = decodedToken.adminId;    
    console.log(decodedToken);
    console.log(employeeId);
    console.log(employeeId.adminId);

    // Find the existing bank details object for the employee
    let bankDetails = await BankDetails.findOne({ employeeId: employeeId });
    if (bankDetails) {
      // Update the existing bank details object with the new form data
      bankDetails.accountholdername = req.body.accountholdername;
      bankDetails.mobilenumber = req.body.mobilenumber;
      bankDetails.acctype = req.body.acctype;
      bankDetails.bankname = req.body.bankname;
      bankDetails.branchname = req.body.branchname;
      bankDetails.ifsc = req.body.ifsc;
      bankDetails.pannumber = req.body.pannumber;
      bankDetails.bankaccnumber = req.body.bankaccnumber;
    } else {
      // Create a new bank details object and populate it with form data
      bankDetails = new BankDetails({
        employeeId: employeeId,
        adminId: adminId,
        accountholdername: req.body.accountholdername,
        mobilenumber: req.body.mobilenumber,
        acctype: req.body.acctype,
        bankname: req.body.bankname,
        branchname: req.body.branchname,
        ifsc: req.body.ifsc,
        pannumber: req.body.pannumber,
        bankaccnumber:req.body.bankaccnumber,
      });
    }

    // Save the bank details object to the database
    const savedBankDetails = await bankDetails.save();
    console.log("Bank details added/updated successfully. Employee ID:", employeeId, "Admin ID:", adminId, "Form data:", savedBankDetails);
    res.send(savedBankDetails);
  } catch (err) {
    console.log("Error adding/updating bank details:", err.message);
    console.log('Error decoding JWT token:', err.message);
    return res.status(401).send('Unauthorized');
  }
});


router2.get("/bankDetails", async (req, res) => {
  // Get the JWT token from the request headers or cookies
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  try {
    // Verify the JWT token and extract the employee ID
    const decodedToken = jwt.verify(token, config.JWT_SECRET);
    const employeeId = decodedToken.employeeId;

    // Find the bank details for the employee with the matching ID
    const bankDetails = await BankDetails.findOne({ employeeId });
    if (!bankDetails) {
      console.log("Bank details not found for employee ID:", employeeId);
      return res.status(404).json({ error: "Bank details not found" });
    }

    // Return the bank details as a response
    console.log("Bank details retrieved successfully for employee ID:", employeeId);
    res.send(bankDetails);
  } catch (err) {
    console.log("Error retrieving bank details:", err.message);
    console.log('Error decoding JWT token:', err.message);
    return res.status(401).send('Unauthorized');
  }
});





router2.get("/bankDetailsadmin", async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const decodedToken = jwt.verify(token, config.JWT_SECRET);
    console.log("Decoded token:", decodedToken); // Debugging purposes only
    const adminId = decodedToken.adminId;
  
    // Check if the admin with the given ID exists
    const admin = await Admin.findById(adminId);
    if (!admin) {
      console.log("Admin not found with ID:", adminId);
      return res.status(404).json({ error: "Admin not found" });
    }

    // Retrieve bank details of all employees
    const bankDetails = await BankDetails.find();

    // Return the bank details as a response
    console.log("Bank details retrieved successfully");
    res.send(bankDetails);
  } catch (err) {
    console.log("Error retrieving bank details:", err.message);
    console.log('Error decoding JWT token:', err.message);
    return res.status(401).send('Unauthorized');
  }
});





router2.delete('/deleteEmployee', async (req, res) => {
  try {
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
      throw new Error('Authorization header is missing');
    }

    const token = authorizationHeader.split(' ')[1];
    const tokenData = jwt.verify(token, config.JWT_SECRET);
    const adminId = tokenData.adminId;
    const employeeId = tokenData.employeeId;

    console.log('Admin ID:', adminId);
    console.log('Employee ID:', employeeId);
    console.log('Started deleting employee');
    console.log('authorizationHeader:', authorizationHeader);
    console.log('token:', token);
    console.log('tokenData:', tokenData);
    console.log('adminId:', adminId);
    console.log('employeeId:', employeeId);

    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).send({ message: 'Admin not found' });
    }
    
    console.log('Admin:', admin);

    const employee = await Employee.findById(employeeId);
    if (!employee) {
      console.log(`Employee not found for id ${employeeId}`);
      return res.status(404).send({ message: 'Employee not found' });
    }
    console.log('Employee:', employee);

    await Employee.deleteOne({_id: employeeId});
    console.log('Employee deleted:', employee);

    // Send email to admin about employee deletion using NodeMailer
    const mailOptions = {
      from: "surendrawankhade1973@gmail.com",
      to: admin.email,
      subject: `Employee ${employee.firstName} ${employee.lastName} has been deleted from Cling Multi Solution`,
      html: `<p>Hello ${admin.firstName},</p>
             <p>The employee ${employee.firstName} ${employee.lastName} has been deleted from Cling Multi Solution by ${admin.firstName} ${admin.lastName}.</p>
             <p>Thank you!</p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log('Error:', error.message);
      } else {
        console.log('Email sent:', info.response);
      }
    });

    res.send({ message: 'Employee deleted successfully' });

  } catch (err) {
    console.log('Error:', err.message);
    res.status(400).send({ message: err.message });
  }
});


export default router2;
