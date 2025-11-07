import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";
import {v2 as cloudinary} from "cloudinary"
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
    avatarPublicID:avatar.public_id,
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
 console.log(req.body);
  const {email, userName, password} = req.body
 

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

const changeCurrentPassword = asyncHandler(async(req,res)=>{
  const {oldPassword,newPassword} = req.body
  const user = await User.findById(req.user?._id)
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError(400,"Invalid old password")
  }

  user.password = newPassword
  await user.save({validateBeforeSave:false})

  return res
  .status(200)
  .json(new ApiResponse(200,{},"Password saved successfully"))

})

const getCurrentUser = asyncHandler(async(req,res)=>{
  console.log(req.user);
  return res.status(200)
  .json(new ApiResponse(
    200,
    await req.user,
    "current user fetched successfully"
  ))
})

const updateAccountDetails = asyncHandler(async(req,res)=>{
  const {fullName,email} = req.body
  if(!fullName || !email){
    throw new ApiError(400,"All fileds are required")
  }
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        fullName:fullName,
        email:email
      }
    },
    { new:true }

  ).select("-password -refreshToken")

  return res
  .status(200)
  .json(200,user,"Accounts details updated Successfully")
})

const updateUserAvatar = asyncHandler(async(req,res)=>{
  const avatarLocalPath = req.file?.path
  if(!avatarLocalPath){
    throw new ApiError(400,"Avatar file is missing")
  }
  const avatar = await uploadOnCloudinary(avatarLocalPath)
  
  if(!avatar.url){
     throw new ApiError(400,"Error while uploding on avatar")
  }
  
  console.log(req.user);
 
   const oldAvatarPublicId = req.user?.avatarPublicID


  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set:{ avatar:avatar.url,
       avatarPublicID: avatar.public_id
      }
    },{new:true}
  ).select("-password ")

     
   try {
    await cloudinary.uploader.destroy(oldAvatarPublicId);
   } catch (error) {
        throw new ApiError(501,error.message);
   }

   return res.status(200)
  .json(new ApiResponse(
    200,user,"avatar image updated successfully"
  ))
})

const updateUserCoverImage = asyncHandler(async(req,res)=>{
  const coverImageLocalPath = req.file?.path
  if(!coverImageLocalPath){
    throw new ApiError(400,"Cover Image file is missing")
  }
  const coverImage = await uploadOnCloudinary(coverImageLocalPath)
  
  if(!coverImage.url){
     throw new ApiError(400,"Error while uploding on cover image")
  }

  const user = await User.findByIdAndDelete(req.user?._id,
    {
      $set:{ coverImage:coverImage.url}
    },{new:true}
  ).select("-password -refreshToken")

  return res.status(200)
  .json(200,user,"cover image updated successfully")
})

const getUserChannelProfile = asyncHandler(async(req,res)=>{
  const {username} = req.params
  if(!username?.trim()){
    throw new ApiError(400,"User name is missing")
  }

  const channel = await User.aggregate([
    {
      $match:{
        username:username?.toLowerCase()
      },
      $lookup:{
        from:"subscriptions",
        localField:"_id",
        foreignField:"channel",
        as:"subscribers"
      },
      $lookup:{
        from:"subscriptions",
        localField:"_id",
        foreignField:"subscriber",
        as:"subscribedTo"
      },
      $addFields:{
        subscribersCount:{
          $size:"$subscribers"
        },
        channelSubscribedToCount:{
          $size:"$subscribedTo"
        },
        isSubscribed:{
        $cond:{
          if:{$in:[req.user?._id,"$subscribers.subsriber"]},
          then:true,
          else:false
        }
      }

      }
      
    },
      {
        $project:{
          fullName:1,
          username:1,
          subscribersCount:1,
          channelSubscribedToCount:1,
          isSubscribed:1,
          avatar:1,
          coverImage:1,
          email:1
        }
      }
  ])

  if(!channel?.length){
    throw new ApiError(404,"channel does not exists")
  }
  return res
  .status(200)
  .json(
    new ApiResponse(200,channel[0],"User channel fetched successfully")
  )
})

 const getWatchHistory = asyncHandler(async(req,res)=>{
  const user = await User.aggregate([
    {
      $match:{
        _id: mongoose.Types.ObjectId(req.user._id)
      }
    },
    {
      $lookup:{
        from:"video",
        localField:"watchHistory",
        foreignField:"_id",
        as:"watchHistory",
        pipeline:[{
          $lookup:{
            from:"users",
            localField:"owner",
            foreignField:"_id",
            as:"owner",
            pipeline:[{
              $project:{
                fullName:1,
                userName:1,
                avatar:1
              }
            },
            {
              $addFields:{
                owner:{
                  $first:"$owner"
                }
              }
            }
          ]
          }
        }]

      }
    }
  ])
  return res.status(200)
  .json(
    new ApiResponse(
      200,user[0].watchHistory,
      "Watch history fetched successfully "
    )
  )
 })

export {registerUser,
  loginUser,
  logOutUser,
  refereshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserCoverImage,
  updateUserAvatar,
  getUserChannelProfile,
  getWatchHistory

  
}