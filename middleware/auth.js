
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import User from "../model/User.model.js";
import config from "../router/config.js";
import cookieParser from 'cookie-parser';

export default async function loginUser(req, res) {
  const { email, password } = req.body;
  try {
    // check if user exists in database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // check if password is correct
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // generate token
    const token = generateToken(user);

    // save token in database
    if (!user.tokens) {
      user.tokens = [];
    }
    user.tokens = user.tokens.concat({ token });
    await user.save();

    // send response with token and user data
    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        email: user.email,
        name: user.name,
      },
    });
  } catch (err) {
   console.log(err)
  }
};

function generateToken(user) {
  const token = jwt.sign(
    {
      userId: user._id,
      username: user.username,
      email: user.email,
    },
    config.JWT_SECRET,
    {
      expiresIn: "1h",
    }
  );
  return token;
}

async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Authorization header missing" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decodedToken = jwt.verify(token, config.JWT_SECRET);

    // find user by token and token's user ID
    const user = await User.findOne({ _id: decodedToken.userId, "tokens.token": token });
    if (!user) {
      throw new Error();
    }

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    res.status(401).json({ error: "Authentication failed" });
  }
}


export {verifyToken , loginUser}