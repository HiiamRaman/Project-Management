import { app } from "./app.js";
import dotenv from "dotenv";
import { connectDB } from "./db/index.js";
dotenv.config();

const port = process.env.PORT || 3000;

//mongodb connection
connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(` app listening on port http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.log("Mongodb connection Error", error);
    process.exit(1);
  });
