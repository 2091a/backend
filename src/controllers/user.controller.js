import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req,res)=>{
   //get user details from frontend
   //validation - not empty
   //check if user already exists: username, email 
   //check for images, check for avatar 
   //upload them to cloudinary 
   //create user object - creat entry in db 
   //remove password and refresh token filed from response 
   //check for user creation 
   // return response

   const {fullName,email,userName,password} = req.body
   console.log(email);

   // to check multiple filed for same condection in a single if condection 
   if(
    [fullName,email,userName,password].some((filed)=> 
    filed?.tirm()==="")
   ){
    throw new ApiError(400,"All fileds are required")
   }

   const existedUser = User.findOne({
    $or: [{email},{userName}]
   })

   if(existedUser){
    throw new ApiError(409,"User with email or username alredy exists")
   }

   const avatarLocalPath = req.files?.avatar[0]?.path;
   const coverImageLocalPath = req.files?.coverImage[0]?.path;

   if(!avatarLocalPath){
    throw new ApiError(400,"Avatar file is required")
   }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if(!avatar){
    throw new ApiError(400,"Avatar file is required")
  }

  const user = await User.create({
    fullName,
    avatar:avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    userName:userName.toLowerCase()
  })

  const createUser = await User.findById(user._id).select(
    "-password -refreshToken"
  )

  if(!createUser){
    throw new ApiError(500,"Something went wrong while registering the user")
  }


  return res.status(201).json(
    new ApiResponse(200,createUser,"User registered Successfully ")
  )


   
})

export {registerUser}