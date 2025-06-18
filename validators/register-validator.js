import { checkSchema } from "express-validator";

export default checkSchema({
    firstName: {
        notEmpty: true,
        errorMessage: "First Name is Required",
        isString: true,
        errorMessage: "First Name must be a String",
        trim: true,
    },
    lastName: {
        notEmpty: true,
        errorMessage: "Last Name is Required",
        trim: true,
        isString: {
            errorMessage: "Last Name must be a String"
        }
    },
    email: {
        notEmpty: true,
        errorMessage: "Email is Required",
        trim: true,
        isEmail: {
            errorMessage: "Email must be Valid Email"
        }
    },
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