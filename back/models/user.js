import mongoose from 'mongoose';
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
const Schema = mongoose.Schema;

const userSchema = new Schema({
    email:{
        type: String,
        required:true
    },
    password:{
        type: String,
        required:true
    },
    name:{
        type:String,
        required:true
    },
    token:{
        type:String
    }
});
userSchema.methods.comparePass = function (plain){
    return bcrypt
    .compare(plain, this.password)
    .then((isMatch) => isMatch)
    .catch((err)=> err);
}
userSchema.methods.generateToken = function (){
    const token = jwt.sign(this._id.toHexString(), "secretToken");
    this.token = token;
    return this.save()
    .then((user) => user)
    .catch((err) => err);
}

export default mongoose.model('User', userSchema);