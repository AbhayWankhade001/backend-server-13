// import mongoose from "mongoose";

// import { MongoMemoryServer } from "mongodb-memory-server";
// import ENV from '../router/config.js'

// async function connect(){

//     const mongod = await MongoMemoryServer.create();
//     const getUri = mongod.getUri();

//     mongoose.set('strictQuery', true)
//     // const db = await mongoose.connect(getUri);
//     const db = await mongoose.connect(ENV.ATLAS_URI);
//     console.log("Database Connected")
//     return db;
// }

// export default connect;
import mongoose from "mongoose";
import ENV from '../router/config.js';

async function connect(){
    const db = await mongoose.connect(ENV.ATLAS_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        // serverSelectionTimeoutMS: 3000, // Add this option
    });
    console.log("Database Connected");
    return db;
}

export default connect;

// import mongoose from "mongoose";
// import { MongoMemoryServer } from "mongodb-memory-server";
// import ENV from "../router/config.js";

// async function connect() {
//   const mongod = await MongoMemoryServer.create();
//   const getUri = mongod.getUri();

//   mongoose.set("strictQuery", true);
//   mongoose.set("useCreateIndex", true);
//   // Remove the `useFindAndModify` option
//   // mongoose.set('useFindAndModify', false);

//   // Update the connection string to use `getUri` from the `MongoMemoryServer`
//   const db = await mongoose.connect(getUri || ENV.ATLAS_URI, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//   });

//   console.log("Database Connected");
//   return db;
// }
// export default connect;
