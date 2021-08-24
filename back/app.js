import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import {body, validationResult} from 'express-validator';
import User from './models/user.js';
import bcrypt from 'bcryptjs';

dotenv.config();
const app = express();
const PORT = 3000;
app.use(express.json());
app.use('/', (req,res, next)=>{
    // console.log(`allowed cors : ${req.originalUrl}`);
    // res.set('Access-Control-Allow-Origin','http://localhost:8080')        
    res.set('Access-Control-Allow-Origin','*'); //cors 전체 허용
    res.set('Access-Control-Allow-Methods', '*');
    res.set("Access-Control-Allow-Headers", "*");
     next();
});
app.post('/auth/signup', [
body('email')
.isEmail()
.withMessage('Please type valid email')
.custom((value)=>{
    return User.findOne({email:value}).then((userDoc)=>{
        if(userDoc){
            return Promise.reject('E-Mail address already exists');
        }
    });
}),
body('password')
.trim()
.isLength({min:6})
.withMessage('Password must be greater than 6 charcaters'),
body('name')
.trim()
.not().isEmpty()
.withMessage('Name field is required')
], async(req, res, next) =>{
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        const error = new Error('Validation failed');
        error.statusCode = 422;
        error.data = errors.array();
        return next (error);
    }
    console.log(req.body);
    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;

    // 유저 이메일 체크
    
    // 패스워드 해시화 해서 데이터 저장
    try{
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new User({
            email,
            password: hashedPassword,
            name
        });
        const result = await user.save();
        res.status(201).json({
            message:"User created",
            userId: result._id
        })
    }
    catch(err){
        if(!err.statusCode){
            err.statusCode = 500;
        }
        next(err);
    }

});

app.use((error, req, res, next) =>{
    const status = error.statusCode || 500;
    const message = error.message;
    const data = error.data;
    res.status(status).json({
        message, data
    })
})
app.post("/login", async (req, res) => {

    User.findOne({ email: req.body.email }, (err, user) => {
        if(err){
            return res.json({
                loginSuccess : false,
                message: "Id does not found"
            });
        }
        user
            .comparePass(req.body.password)
            .then((isMatch) => {
                if (!isMatch) {
                    return res.json({
                        loginSuccess: false,
                        message: "password does not found"
                    });
                }
                
                user
                    .generateToken()
                    .then((user) => {
                        res
                        .cookie("x_auth", user.token)
                        .status(200)
                        .json({loginSuccess: true, userId: user._id });

                    })
                    .catch((err) =>{
                        res.status(400).send(err);
     
                    });
            })
            .catch((err) => res.json({ loginSuccess: false, err }));
    })
});
mongoose.connect(`mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.3n1ev.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(() => {
    app.listen(3000, () => {
        console.log(`listing to port ${PORT}`);

    });

}).catch(err => console.log(err));