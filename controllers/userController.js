import UserModel from '../models/User.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import transporter from '../config/emailConfig.js';

class UserController {
    static userRegistration = async (req, res) => {
        const { name, email, password, password_confirmation, tc } = req.body
        const user = await UserModel.findOne({ email: email })
        if (user) {
            res.send({ "status": "failed", "message": "Email already exists" })
        } else {
            if (name && email && password && password_confirmation && tc) {
                if (password === password_confirmation) {
                    try {
                        const salt = await bcrypt.genSalt(10)
                        const hashPassword = await bcrypt.hash(password, salt)
                        const doc = new UserModel({
                            name: name,
                            email: email,
                            password: hashPassword,
                            tc: tc
                        })
                        await doc.save()
                        const saved_user = await UserModel.findOne({ email: email })
                        // Generate JWT Token
                        const token = jwt.sign({ userID: saved_user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' })
                        res.status(201).send({ "status": "success", "message": "Registration Success", "token": token })
                    } catch (error) {
                        console.log(error)
                        res.send({ "status": "failed", "message": "Unable to Register" })
                    }
                } else {
                    res.send({ "status": "failed", "message": "Password and Confirm Password doesn't match" })
                }
            } else {
                res.send({ "status": "failed", "message": "All fields are required" })
            }
        }
    }

    static userLogin = async (req, res) => {
        try {
            const { email, password } = req.body
            if (email && password) {
                const user = await UserModel.findOne({ email: email })
                if (user != null) {
                    const isMatch = await bcrypt.compare(password, user.password)
                    if ((user.email === email) && isMatch) {
                        // Generate JWT Token
                        const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' })
                        res.send({ "status": "success", "message": "Login Success", "token": token })
                    } else {
                        res.send({ "status": "failed", "message": "Email or Password is not Valid" })
                    }
                } else {
                    res.send({ "status": "failed", "message": "You are not a Registered User" })
                }
            } else {
                res.send({ "status": "failed", "message": "All Fields are Required" })
            }
        } catch (error) {
            console.log(error)
            res.send({ "status": "failed", "message": "Unable to Login" })
        }
    }

    static changeUserPassword = async (req, res) => {
        const { password, password_confirmation } = req.body
        if (password && password_confirmation) {
            if (password !== password_confirmation) {
                res.send({ "status": "failed", "message": "Password and Confirm Password doesn't match" })
            } else {
                const salt = await bcrypt.genSalt(10)
                const hashPassword = await bcrypt.hash(password, salt)
                await UserModel.findByIdAndUpdate(req.user._id, { $set: { password: hashPassword } })
                res.send({ "status": "success", "message": "Password changed successfully" })
            }
        }
        else {
            res.send({ "status": "failed", "message": "Both fields are required" })
        }
    }

    static loggedUser = async (req, res) => {
        res.send({ "user": req.user });
    }

    static sendUserPasswordEmail = async (req, res) => {
        const { email } = req.body
        if (email) {
            const user = await UserModel.findOne({ email: email })
            if (user) {
                const secret = user._id + process.env.JWT_SECRET_KEY;
                const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '15m' })
                const link = `http://localhost:3000/api/user/reset/${user._id}/${token}`
                console.log(link)

                //send Email
                let info = await transporter.sendMail({
                    from: process.env.EMAIL_FROM,
                    to: user.email,
                    subject: "Reset Password Link",
                    html: `<a href=${link}>Click Here</a> to Reset Your Password`
                });
                res.send({ "status": "success", "message": "check email to change password" })
            }
            else {
                res.send({ "status": "failed", "message": "Email dosen't exist" })
            }
        } else {
            res.send({ "status": "failed", "message": "Email field required" })
        }
    }

    static userPasswordReset = async (req, res) => {
        const { password, password_confirmation } = req.body;
        const { id, token } = req.params;
        const user = await UserModel.findById(id)
        const new_secret = user._id + process.env.JWT_SECRET_KEY
        try {
            jwt.verify(token, new_secret)
            if (password && password_confirmation) {
                if (password === password_confirmation) {
                    const salt = await bcrypt.genSalt(10)
                    const hashPassword = await bcrypt.hash(password, salt)
                    await UserModel.findByIdAndUpdate(user._id, { $set: { password: hashPassword } })
                    res.send({ "status": "success", "message": "Password reset successfully" })
                }
                else {
                    res.send({ "status": "failed", "message": "Both passwords do not match" })
                }
            }
            else {
                res.send({ "status": "failed", "message": "all fields required" })
            }
        } catch (error) {
            res.send({ "status": "failed", "message": "Invalid token" })
        }
    }
}
export default UserController