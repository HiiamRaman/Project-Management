import Mailgen from "mailgen";
import { ApiError } from "./apiError.js";
import nodemailer from "nodemailer";
//Create a transporter Every email you send goes through a transporter—an object that knows how to deliver messages to your chosen email service.

const transporter = nodemailer.createTransport({
  host: "smtp.example.com",
  port: 587,
  auth: {
    user: process.env.MAIL_SMTP_USER,
    pass: process.env.MAIL_SMTP_PASS,
  },
});
// Configure mailgen by setting a theme and your product info

const mailGenerator = new Mailgen({
  theme: "default",
  product: {
    // Appears in header & footer of e-mails
    name: "Project Management",
    link: "https://projectmanagement.com",
    // Optional product logo
    // logo of ypur product
  },
});

//send Email
export const sendEmail = async function (options) {
  try {
    const emailBody = mailGenerator.generate(options.mailgenContent);
    const emailText = mailGenerator.generatePlaintext(options.mailgenContent);
    const mailOptions = {
      from: process.env.MAIL_SMTP_USER,
      to: options.email,
      subject: options.subject,
      html: emailBody,
      text: emailText,
    };
    return transporter.sendMail(mailOptions);
  } catch (error) {
    console.log("Email Errorr : ", error);
    throw new ApiError(500, "Email sending failed");
  }
};

export const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to Mailgen! We're very excited to have you on board.",
      action: {
        instructions: "To get started with Mailgen, please click here:",
        button: {
          color: "#22BC66", // Optional action button color
          text: "Confirm your account",
          link: verificationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};
export const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to Mailgen! We're very excited to have you on board.",
      action: {
        instructions: "To get started with Mailgen, please click here:",
        button: {
          color: "#22BC66", // Optional action button color
          text: "Confirm your account",
          link: passwordResetUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};
