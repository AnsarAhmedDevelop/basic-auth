import mongoose from "mongoose"

const userSchema = mongoose.Schema(
    {
        firstName: { type: String, required: true },
        lastName: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        role: {
            type: String,
            enum: ['Admin', 'User', 'SuperAdmin'],
            default: 'User'
        },
        isVerified: {
            type: Boolean,
            default: false
        },
        verifyOtp: {
            type: String,
            default: ""
        },
        verifyOtpExpireAt: {
            type: Number,
            default: 0
        },
        resetOtp: {
            type: String,
            default: ""
        },
        resetOtpExpireAt: {
            type: Number,
            default: 0
        },
        avatar: {
            type: String,
            get: (image) => {
                if (image) {
                    const index = image.search('uploads');
                    if (index != -1) {
                        return `${process.env.BACKEND_URL}/${image}`;
                    } else {
                        return `${image}`;
                    }
                }
            }
        }
    }, {
    timestamps: true, toJSON: {getters: true}
}
)

const userModel = mongoose.model("User", userSchema)

export default userModel