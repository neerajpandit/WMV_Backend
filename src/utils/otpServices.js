import fetch from 'node-fetch';

export const sendOTP = async (phoneNo, otp) => {
    try {
        const phone = phoneNo.replace("+", "");
        // const messages = message;
        const message = `Dear Customer, Your OTP for mobile number verification is ${otp}. Please do not share this OTP to anyone - Firstricoz Pvt. Ltd.`;
        const url = `https://smsgw.tatatel.co.in:9095/campaignService/campaigns/qs?dr=false&sender=FRICOZ&recipient=${phone}&msg=${encodeURIComponent(message)}&user=FIRSTR&pswd=First^01&PE_ID=1601832170235925649&Template_ID=1607100000000306120`;

        const response = await fetch(url);
        const data = await response.json();
        console.log(data); // Assuming the response is JSON
    } catch (error) {
        console.error('Error sending SMS:', error);
    }
};



// export sendOTP;
import crypto from 'crypto'

export function generateOtp(length) {
  // Ensure the length is valid and set to a default of 6 if not provided
  const otpLength = Math.max(4, length); // Minimum 4 digits
  
  // Generate random bytes and convert to an integer
  const otp = crypto.randomInt(0, Math.pow(10, otpLength)).toString().padStart(otpLength, '0');

  return otp;
}