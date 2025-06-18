import { checkSchema } from "express-validator";

export default checkSchema({  
    password: {
        notEmpty: true,
        errorMessage: "Password is Required",
        trim: true,
        isLength: {
            options: { min: 6 },
            errorMessage: 'Password should be at least 6 chars',
        },
        matches: {
            options: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
            errorMessage: "Password must contain letters, numbers, and special characters"
        }
    },

})