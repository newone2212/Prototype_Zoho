const mongoose = require('mongoose');
mongoose.connect("mongodb+srv://paru123:jaigopal123_@cluster0.trzg2kg.mongodb.net/oyasis").then((db)=>{
    console.log("connection is succesful");
}).catch((err)=>{
    console.log("no connection",err);
})

//setting up connection with db
const db = mongoose.connection;


// db.on('error', (err) => {
//   console.error('connection error:', err);
// });
//  //code to create Super Admin
// db.once('open', function() {
//   console.log("Connected to MongoDB!");
//   const User = require("../models/adminModel");
//   User.findOne({ admin_name: "superAdmin" }).then((user) =>{
//     if (!user) {
//       console.log("Admin user does not exist, creating...");
//       const admin = new User({
//         admin_name: "superAdmin",
//         password: "secret",
//         phone: 9314604196,
//         address:"super adimin address is null",
//         email:"parth.wfa@gmail.com",
//         requestState:"Approved"
//       });
//       admin.save().then(()=> {
//         console.log(" superAdmin user created successfully.");
//       }).catch((error)=>{
//         console.log(error);
//         //console.log("superAdmin user already exists.");
//       });
//     } else {
//       console.log("superAdmin user already exists.");
//     }
//    });
// });


//mongodb+srv://paru123:jaigopal123_@cluster0.trzg2kg.mongodb.net/test

