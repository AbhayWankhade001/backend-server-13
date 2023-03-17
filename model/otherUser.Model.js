// import mongoose from "mongoose";

// export const FormSchema = new mongoose.Schema({
//   bankAccount: {
//     type: String,
//     required: true
//   },
//   ifscCode: {
//     type: String,
//     required: true
//   },
//   // add any additional fields you need for the /form API
// });


// export default mongoose.model( 'Form',FormSchema);



import mongoose from "mongoose";

const FormSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User'
  },
  bankAcc: {
    type: String,
    required: true
  },
  ifsc: {
    type: String,
    required: true
  },
  adharNumber: {
    type: String,
    required: true
  },
  panNumber: {
    type: String,
    required: true
  },
  address: {
    type: String,
    required: true
  }
});


export default mongoose.model( 'Form',FormSchema);
