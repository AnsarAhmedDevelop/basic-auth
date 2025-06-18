import { checkSchema } from "express-validator";

export default checkSchema({  
    email:{
        notEmpty:true,
        errorMessage:"Email is Required",
        trim:true,
        isEmail:{
            errorMessage:"Email Should be Valid Email"
        }
    },
    password:{
        notEmpty:true,
        errorMessage:"Password is Required",
        trim:true,
        isLength:{
            options:{min: 6},
            errorMessage:"Password should be at least 6 characters"
        },
        matches: { 
            options: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
            errorMessage:"Password must contain letters, numbers, and special characters"
        }
    }
})