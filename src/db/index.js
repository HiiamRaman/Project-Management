import mongoose from 'mongoose'


export const connectDB =  async function () {
  
try {
     await mongoose.connect(process.env.MONGO_URI);
     console.log("MongoDb connected successfully !!!")
} catch (error) {
    console.log("MongoDb connection Failed :",error)
    process.exit(1)
}
  

 
}