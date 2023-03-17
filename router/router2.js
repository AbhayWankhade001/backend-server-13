import express from "express";
import { loginUser, verifyToken } from "../middleware/auth.js";
import User,{Employee} from "../model/User.model.js";
import mongoose from "mongoose";
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



export default router2;
