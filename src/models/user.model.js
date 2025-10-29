import mongoose , {Schema} from "mongoose"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs";

const userSchema = new Schema(
    {
        userName:{
            type:String,
        required:true,
            unique:true,
            lowercase: true,
            trim: true,
            index: true
        },
        email:{
             type:String,
            required:true,
            unique:true,
            lowercase: true,
            trim: true,
        },
        fullName:{
             type:String,
            required:true,
            trim: true,
            index: true
        },
        avatar:{
            type:String, 
            required: true,
        },
        coverImage:{
            type:String
        },
        watchHistory:[
            {
                type:Schema.Types.ObjectId,
                ref:"Video"
            }
        ],
        password:{
            type:String,
            required:[true,"Password is required"]
        },
        refreshToken:{
            type:String
        }
    },{timestamps:true});

userSchema.pre("save",async function(next){
    if(!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password,10);
    next();
})



userSchema.method.isPasswordCorrect= async function (password) {
    return await bcrypt.compare(password,this.password);
}


userSchema.methods.genrateAccessToken = function (){
    return jwt.sign({
        _id : this._id,
        email: this.email,
        userName : this.userName,
        fullName : this.fullName
    },process.env.Access_Token_Secret,
    {expiresIn:process.env.Access_Token_Expiry }
)
}

userSchema.methods.genrateRefreshToken = function (){
    return jwt.sign({
        _id : this._id,
    },process.env.Refresh_Token_Secret,
    {expiresIn:process.env.Refresh_Token_Expiry }
)
}
export const User = mongoose.model("User",userSchema);