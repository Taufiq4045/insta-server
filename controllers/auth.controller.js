const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const sgMail = require("@sendgrid/mail");
const nodemailer = require("nodemailer");



sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const User = require("../models/user.model");

// SignUp Controller
exports.signup = (req, res) => {
	const { name, email, password } = req.body;
	// Verifying if one of the fields is Empty
	if (!name || !password || !email) {
		return res.json({ error: "Please submit all required field" });
	}
	// Else we search the user with the credentials submitted
	User.findOne({ Email: email })
		.then((savedUser) => {
			// Verify if the user exist in the DB
			if (savedUser) {
				return res.json({ error: "This Email Is Already Used !" });
			}
			// We Hash the pwd before save into DB, more the number is high more it's more secure
			bcrypt.hash(password, 12).then((hashedPwd) => {
				const user = new User({
					Name: name,
					Email: email,
					Password: hashedPwd,
				});
				// We save our new user to DB
				user.save()
					.then((user) => {
						// // after saving the user into DB we send a confirmation email using SendGrid
						// const email = {
						// 	from: "no-reply@insta-clone.com",
						// 	to: user.Email,
						// 	subject: "Your account has been created successfully",
						// 	html: "<h1>Welcome to InstaClone</h1>",
						// };
						// sgMail.send(email);
						// res.json({ message: "Saved successfully " });

						// after saving the user into DB we send a confirmation email using NodeMailer
						var transporter = nodemailer.createTransport({
							service:'gmail',
							auth:{
								user: process.env.MAILER_USERNAME,
								pass: process.env.MAILER_PASSWORD
							}
						});
						
						var mailOptions={
							from:'no-reply@insta-clone.com',
							to: user.Email,
							subject: "Your account has been created successfully",
							text: "Welcome to InstaClone"
						};
						
						transporter.sendMail(mailOptions,(error,info)=>{
							if(error){
								console.log("Error in sending mail",error)
							}
							else{
								console.log('Email sent: ' + info.response);  
							}
						})

						res.json({ message: "Saved successfully " });
					})
					.catch((err) => {
						console.log(err);
					});
			});
		})
		.catch((err) => {
			console.log(err);
		});
};

// SignIn Controller
exports.signin = (req, res) => {
	const { email, password } = req.body;
	// Verification for an empty field
	if (!email || !password) {
		return res.json({ error: "Please provide Email or Password" });
	}
	// Check if email exist in our DB
	User.findOne({ Email: email })
		.then((savedUser) => {
			if (!savedUser) {
				return res.json({ error: "Invalid Email or Password" });
			}
			bcrypt.compare(password, savedUser.Password).then((doMatch) => {
				if (doMatch) {
					// we will generate the token based on the ID of user
					const token = jwt.sign({ _id: savedUser._id }, process.env.JWT_SECRET);
					// retrieve the user info details and send it to the front
					const { _id, Name, Email, Followers, Following, Bookmarks } = savedUser;
					res.json({ token, user: { _id, Name, Email, Followers, Following, Bookmarks } });
				} else {
					return res.status(401).json({
						error: "Invalid Email or Password",
					});
				}
			});
		})
		.catch((err) => {
			console.log(err);
		});
};

// Reset Password Controller
exports.resetPwd = (req, res) => {
	crypto.randomBytes(32, (err, buffer) => {
		if (err) {
			console.log(err);
		}
		const token = buffer.toString("hex");
		User.findOne({ Email: req.body.email }).then((user) => {
			if (!user) {
				console.log("simple check of the error source");
				return res.json({ error: "No User exists with that email" });
			}

			user.ResetToken = token;
			user.ExpirationToken = Date.now() + 600000; // 10min in ms
			user.save().then((result) => {
				// this section will be fully functional after adding the SendGrid API Key
				// in order to use this feature
				// the following is an example of Email template

				// const email = {
				// 	to: user.Email,
				// 	from: "no-reply@insta-clone.com",
				// 	subject: "Password Reset",
				// 	html: `
				//      <p>A request has been made to change the password of your account </p>
				// 	 <h5>click on this <a href="http://localhost:3000/reset/${token}">link</a> to reset your password</h5>
				// 	 <p> Or copy and paste the following link :</p>
				// 	 <h5>"http://localhost:3000/reset/${token}"</h5>
				// 	 <h5>The link is only valid for 10min</h5>
				// 	 <h5>If you weren't the sender of that request , you can just ignore the message</h5>
				//      `,
				// };
				// sgMail
                // .send(email)
                // .then((response) => {
                // console.log(response[0].statusCode)
                // console.log(response[0].headers)
                // })
                // .catch((error) => {
                // console.error(error)
                // })

				// after saving the user into DB we send a confirmation email using NodeMailer
				var transporter = nodemailer.createTransport({
					service:'gmail',
					auth:{
						user: process.env.MAILER_USERNAME,
						pass: process.env.MAILER_PASSWORD
					}
				});
				
				var mailOptions={
					from:'no-reply@insta-clone.com',
					to: user.Email,
					subject: "Password Reset",
					text: `
					     A request has been made to change the password of your account 
						 click on this "http://localhost:3001/reset/${token}" to reset your password
						 Or copy and paste the following link : "http://localhost:3001/reset/${token}"
						 The link is valid only for 10min
						 If you weren't the sender of that request , just ignore the email.
					     `
				};
				
				transporter.sendMail(mailOptions,(error,info)=>{
					if(error){
						console.log("Error in sending mail",error)
					}
					else{
						console.log('Email sent: ' + info.response);  
					}
				})

				res.json({ message: "check your Email Inbox" });
				
			}).catch((err) => {
				console.log(err);
			});
		});
	});
};

// New Password Controller
exports.newPwd = (req, res) => {
	const Password = req.body.password;
	const Token = req.body.token;
	User.findOne({ ResetToken: Token, ExpirationToken: { $gt: Date.now() } })
		.then((user) => {
			if (!user) {
				return res.status(422).json({ error: "Session expired ! Try Again with a new Request" });
			}
			bcrypt.hash(Password, Number(12)).then((HashPwd) => {
				console.log(HashPwd)
				console.log(user.Email);
				user.Password = HashPwd;
				user.ResetToken = undefined;
				user.ExpirationToken = undefined;
				user.save().then(() => {
					res.json({ message: "Password Updated successfully" });
				}).catch((err) => {
					console.log(err);
				});
			}).catch((err) => {
				console.log(err);
			});
		})
		.catch((err) => {
			console.log(err);
		});
};