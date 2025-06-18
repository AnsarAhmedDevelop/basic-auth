import { checkSchema } from "express-validator";

export default checkSchema({
    firstName:{     
        optional:true,   
        isString:{
            errorMessage:"First Name must be a string"
        },
        trim:true
    },
    lastName:{      
        optional:true,  
        trim:true,
         isString:{
            errorMessage:"Last Name must be a string"
        },
    },
    email:{     
        optional:true,   
        trim:true,
        isEmail:{
            errorMessage:"Email Should be Valid Email"
        }
    },
   
})