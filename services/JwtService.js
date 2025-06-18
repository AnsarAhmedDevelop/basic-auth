import jwt from "jsonwebtoken"

const generateToken=(payload)=>{
return jwt.sign(payload,process.env.JWT_SECRET,{expiresIn:'1d'});
}

const verifyToken=(token)=>{
    const decoded=jwt.verify(token,process.env.JWT_SECRET)
    return decoded
}

export {generateToken, verifyToken}