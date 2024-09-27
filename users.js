const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const userSchema = Schema({
    first_name : {
        type:String,
        required:true
    },
    last_name : {
        type:String,
        required:true
    },
    mobile : {
        type:String,
        required:true
    },
    email_id : {
        type : String,
        unique : true,
        required : true
    },
    password : {
        type:String,
        required:true
    }
});

const Users = mongoose.model("users", userSchema);
module.exports = {Users};