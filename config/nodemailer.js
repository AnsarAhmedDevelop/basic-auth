import nodemailer from "nodemailer"

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "ansarahmedn@gmail.com",
    pass: "odvw puvp cpjx eume",
  },
});

export default transporter