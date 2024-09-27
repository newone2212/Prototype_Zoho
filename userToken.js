const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const usertokenSchema = Schema({
    token : {
        type:String,
        required: true
    },
    _userId : {
        type:Schema.Types.ObjectId,
        ref:"users"
    },
    tokenType : {
        type:String,
        enum: ["login", "resetPassword"]
    }
});

const userToken = mongoose.model("usertokens", usertokenSchema);
module.exports = {userToken};