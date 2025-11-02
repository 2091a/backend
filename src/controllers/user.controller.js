import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
const genrateAccessAndRefereshTokens = async(userId)=>{
  try {
    const user = await User.findById(userId)
   const accessToken =  user.genrateAccessToken()
    const refreshToken = user.genrateRefreshToken()

    user.refreshToken = refreshToken
    await user.save({validateBeforeSave:false})

    return {accessToken,refreshToken}

  } catch (error) {
    throw new ApiError(500,"Somting went wrong while generating referesh and access token")
  }
}

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
   //console.log(email);

   // to check multiple filed for same condection in a single if condection 
   if(
    [fullName,email,userName,password].some((filed)=> 
    filed?.trim() ==="")
   ){
    throw new ApiError(400,"All fileds are required")
   }

   const existedUser = await User.findOne({
    $or: [{email},{userName}]
   })

   if(existedUser){
    throw new ApiError(409,"User with email or username alredy exists")
   }

   //console.log(req.files);
   const avatarLocalPath = req.files?.avatar[0]?.path;
   //const coverImageLocalPath = req.files?.coverImage[0]?.path;
   let coverImageLocalPath;
   if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
    coverImageLocalPath = req.files.coverImage[0].path
   }

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

const loginUser = asyncHandler(async(req,res)=>{
  // req body -> data
  // username or email
  //find the user
  // check password 
  //acces and refresh token genrate 
  //send cookie

  const {email,userName,password} = req.body

  if(!(email||userName)){
    throw new ApiError(400,"User name or email is required ")
  }

  const user = await User.findOne({
    $or:[{userName},{email}]
  }
  )

  if(!user){
    throw new ApiError(404,"user does not exist")
  }

  const isPasswordValid = await user.isPasswordCorrect(password)

  if(!isPasswordValid){
    throw new ApiError(401,"Invalid user credentials")
  }

  const {accessToken,refreshToken}= await genrateAccessAndRefereshTokens(user._id)

  const loggdInUser = await User.findById(user._id).select("-password -refreshToken")

  const options={
    httpOnly: true,
    secure: true
  }

  return res.status(200)
  .cookie("accessToken",accessToken,options)
  .cookie("refreshToken",refreshToken,options)
  .json(
    new ApiResponse(
      200,
      {
        user:loggdInUser,accessToken,
        refreshToken
      },
      "User logged in Successfully"
    )
  )



})

const logOutUser = asyncHandler(async(req,res)=>{
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set:{
        refreshToken: undefined
      }
    },
    {
      new: true
    }
  )
  const options={
    httpOnly: true,
    secure: true
  }
  return res.status(200)
  .clearCookie("accessToken",options)
  .clearCookie("refreshToken",options)
  .json(
    new ApiResponse(200,{},"User Logged Out")
  )
})

const refereshAccessToken = asyncHandler (async(req,res)=>{
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken 

  if(!incomingRefreshToken){
    throw new ApiError(401,"unauthorized request")
  }
  try {
    const decodedToken = jwt.verify(incomingRefreshToken,process.env.Refresh_Token_Secret)
    const user = await User.findById(decodedToken?._id)
    
    if(!user){
      throw new ApiError(401,"Invalid refresh token")
    }
  
    if(incomingRefreshToken !== user?.refreshToken){
      throw new ApiError(401,"Refresh tokn is expired or used")
    }
    const options={
      httpOnly:true,
      secure:true
    }
    const {accessToken,newRefreshToken} = await genrateAccessAndRefereshTokens(user._id)
  
    return res
    .status(200)
    .cookies("accessToken",accessToken,options)
    .cookies("refreshToken",newRefreshToken,options)
    .json(
      new ApiResponse(
        200,
        {accessToken,refreshToken:newRefreshToken},
        "Access token refreshed successfully"
  
      )
    )
  } catch (error) {
    throw new ApiError(401,error.message || "Invalid refresh token")
  }
})


export {registerUser,
  loginUser,
  logOutUser,
  refereshAccessToken
}