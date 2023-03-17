import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import connect from './database/conn.js';
import router from './router/route.js';
import bodyParser from 'body-parser'; 
import router2 from './router/router2.js';
import "./router/config.js"
import User from './model/User.model.js';
import cookieParser from 'cookie-parser';
const app = express();
app.use(express.static('public'))
/** middlewares */
app.use(express.json());
app.use(cors());
app.use(morgan('tiny'));
app.disable('x-powered-by'); // less hackers know about our stack
app.use(cookieParser());
router.use(bodyParser.json());
const port = process.env.PORT || 8080;

// Add config variable declaration

/** Https get req */

app.get('/', (req,res)=>{
  res.status(201).json("home get request")
})

app.get('/users', (req,res)=>{
  res.status(201).json("its working finilla😍😍😍😍")
})

/** api routes */
app.use('/api' , router )
app.use("/api", router2);

/** start server */
connect().then(()=>{
  try {
    app.listen(port, () =>{
      console.log(`server connected to https://localhost:${port}`);
    });
  } catch (error) {
    console.log('cannot connect to the server')
  }
}).catch(error => {
  console.log("invalid database connection.... !")
})

// Use config variables

export default app;