import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
export const sendMail = async (to, subject, text) => {
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });
    console.log("hii");
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject,
        text,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log("Email sent successfully");
    } catch (error) {
        console.error("Error sending email:", error);
        throw new Error("Failed to send email");
    }
};

export const sendVerificationEmail = async (email, userId) => {
    try {
        // Generate JWT token
        const token = jwt.sign(
            { id: userId },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "1d" }
        );
        const url = `${process.env.BASE_URL}/verify-email?token=${token}`;
        return url;

        // Send email using Gmail
        // await transporter.sendMail({
        //   from: process.env.EMAIL_USER,
        //   to: email,
        //   subject: 'Email Verification',
        //   html: `<p>Click <a href="${url}">here</a> to verify your email.</p>`,
        // });

        console.log("Verification email sent successfully");
    } catch (error) {
        console.error("Error sending verification email:", error);
        throw new Error("Failed to send verification email");
    }
};

export const verifyEmailToken = (token) => {
    try {
        return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    } catch (error) {
        console.error("Error verifying token:", error);
        throw new Error("Invalid or expired token");
    }
};

// await sendMail(email, 'Password Reset OTP', `Your OTP for password reset is: ${otp}`);
