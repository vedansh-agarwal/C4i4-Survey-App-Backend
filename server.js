// Variable To Track Maintenance Mode
let maintenance_mode = false;

// .env configuration
const dotenv = require("dotenv");
dotenv.config();

// Database Connection
const mysql = require("mysql2");
const db = mysql.createConnection({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD,  
  database: process.env.DB_DATABASE,
});

// Express Configuration
const express = require("express");
const cors = require("cors");
const fileupload = require("express-fileupload");
const port = process.env.PORT || 5000;
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileupload());

// Nodemailer Configuration
const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, 
    auth: {
      user: process.env.SENDER_GMAIL, 
      pass: process.env.SENDER_APP_PASSWORD, 
    }
});

// Imports for Routes
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const aes256 = require("aes256");
const {statusCodes, responseMessages} = require("./statusCodes");
const {emailTemplates} = require("./emailTemplates");
const path = require("path");
const fs = require("fs");

// Middlewares
function checkUserAccess(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if(!token || token == null) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied
        });
    }
    
    try{
        const decoded = jwt.verify(token, process.env.JWT_USER_ACCESS_TOKEN);
        var refresh_token = aes256.decrypt(process.env.USER_REFRESH_TOKEN_ENCRYPTION_KEY, decoded.refresh_token);
        const refresh_decoded = jwt.verify(refresh_token, process.env.JWT_USER_REFRESH_TOKEN);

        db.query("SELECT COUNT(*) FROM users WHERE username = ? AND refresh_token = ?", [decoded.username, refresh_token],
        (err, result) => {
            if(err) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: responseMessages.databaseError, 
                    error_message: err.message
                });
            } else {
                if(result.length == 0) {
                    return res.status(statusCodes.accessDenied).json({
                        response: responseMessages.failure,
                        message: responseMessages.accessDenied
                    });
                } else {
                    req.body.username = decoded.username;
                    req.body.email = refresh_decoded.email;
                    next();
                }
            }
        });
    } catch(err) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied,
            error_message: err.message
        });
    }
}

function checkUserRefresh(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if(!token || token == null) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied
        });
    }

    try{
        const decoded = jwt.verify(token, process.env.JWT_USER_REFRESH_TOKEN);
        db.query("SELECT username FROM users WHERE email = ? AND refresh_token = ?", [decoded.email, token],
        (err, result) => {
            if(err) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: "Database Error", 
                    error_message: err.message
                });
            } else {
                if(result.length === 0) {
                    return res.status(statusCodes.accessDenied).json({
                        response: responseMessages.failure,
                        message: responseMessages.accessDenied
                    });
                } else {
                    req.body.email = decoded.email;
                    req.body.refresh_token = token;
                    req.body.username = result[0].username;
                    next();
                }
            }
        });
    } catch(err) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied,
            error_message: err.message
        });
    }
}

function checkCustomerAccess(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if(!token || token == null) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied
        });
    }

    try{
        const decoded = jwt.verify(token, process.env.JWT_CUSTOMER_ACCESS_TOKEN);
        var refresh_token = aes256.decrypt(process.env.CUSTOMER_REFRESH_TOKEN_ENCRYPTION_KEY, decoded.refresh_token);
        const refresh_decoded = jwt.verify(refresh_token, process.env.JWT_CUSTOMER_REFRESH_TOKEN);

        db.query("SELECT COUNT(*) FROM customers WHERE refresh_token = ?", [refresh_token],
        (err, result) => {
            if(err) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: responseMessages.databaseError, 
                    error_message: err.message
                });
            } else {
                if(result.length == 0) {
                    return res.status(statusCodes.accessDenied).json({
                        response: responseMessages.failure,
                        message: responseMessages.accessDenied
                    });
                } else {
                    req.body.email = refresh_decoded.email;
                    req.body.customer_id = decoded.customer_id;
                    next();
                }
            }
        });
    } catch(err) {
        console.log(err);
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied,
            error_message: err.message
        });
    }
}

function checkCustomerRefresh(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if(!token || token == null) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied
        });
    }

    try{
        jwt.verify(token, process.env.JWT_CUSTOMER_REFRESH_TOKEN);
        var refresh_token = token;

        db.query("SELECT company_email_id, customer_id FROM customers WHERE refresh_token = ?", [refresh_token],
        (err, result) => {
            if(err) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: responseMessages.databaseError, 
                    error_message: err.message
                });
            } else {
                if(result.length == 0) {
                    return res.status(statusCodes.accessDenied).json({
                        response: responseMessages.failure,
                        message: responseMessages.accessDenied
                    });
                } else {
                    req.body.refresh_token = refresh_token;
                    req.body.email = result[0].company_email_id;
                    req.body.customer_id = result[0].customer_id;
                    next();
                }
            }
        });
    } catch(err) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied,
            error_message: err.message
        });
    }
}

function checkAdminToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if(!token || token == null) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied
        });
    }

    try{
        var admin_token = jwt.verify(token, process.env.JWT_ADMIN_TOKEN);
        db.query("SELECT COUNT(*) FROM users WHERE username = ? AND admin_token = ?", [admin_token.username, token],
        (err, result) => {
            if(err) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: responseMessages.databaseError, 
                    error_message: err.message
                });
            } else {
                if(result.length == 0) {
                    return res.status(statusCodes.accessDenied).json({
                        response: responseMessages.failure,
                        message: responseMessages.accessDenied
                    });
                } else {
                    req.body.email = admin_token.email;
                    req.body.username = admin_token.username;
                    next();
                }
            }
        });
    } catch(err) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied,
            error_message: err.message
        });
    }
}

// Routes
app.get("/edify/admin/enable-maintenance-mode", (req, res) => {
    maintenance_mode = true;
    return res.status(statusCodes.success).json({
        response: responseMessages.success,
        message: "Maintenance Mode Enabled"
    });
});

app.get("/edify/admin/disable-maintenance-mode", (req, res) => {
    maintenance_mode = false;
    return res.status(statusCodes.success).json({
        response: responseMessages.success,
        message: "Maintenance Mode Disabled"
    });
});

app.get("/edify/user/generate-access-token", checkUserRefresh, (req, res) => {
    const {refresh_token, username} = req.body;

    const access_token = jwt.sign({
        username,
        refresh_token: aes256.encrypt(process.env.USER_REFRESH_TOKEN_ENCRYPTION_KEY, refresh_token)
    }, process.env.JWT_USER_ACCESS_TOKEN, {expiresIn: "1h"});
    
    return res.status(statusCodes.success).json({
        response: responseMessages.success,
        message: "Access Token Generation Successful",
        access_token
    });
});

app.post("/edify/user/generate-admin-token", (req, res) => {
    const {username, email, admin_password} = req.body;

    if(!username || !email || !admin_password) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    if(admin_password !== process.env.ADMIN_PASSWORD) {
        return res.status(statusCodes.accessDenied).json({
            response: responseMessages.failure,
            message: responseMessages.accessDenied
        });
    }

    const admin_token = jwt.sign({username, email}, process.env.JWT_ADMIN_TOKEN);
    db.query("UPDATE users SET admin_token = ? WHERE username = ?", [admin_token, username],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError, 
                error_message: err.message
            });
        } else {
            if(result.affectedRows === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "User does not exist"
                });
            } else {
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Admin Token Generation Successful",
                    admin_token
                });
            }
        }
    });
});

app.post("/edify/admin/add-admin", checkAdminToken, (req, res) => {
    const {users_username, users_email} = req.body;

    if(!users_username || !users_email) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    const admin_token = jwt.sign({username: users_username, email: users_email}, process.env.JWT_ADMIN_TOKEN);
    db.query("UPDATE users SET admin_token = ? WHERE username = ?", [admin_token, users_username],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError, 
                error_message: err.message
            });
        } else {
            if(result.affectedRows === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "User does not exist"
                });
            } else {
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Admin Token Generation Successful"
                });
            }
        }
    });

});

app.post("/edify/user/check-username", async (req, res) => {
    const {username} = req.body;

    if(!username) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    let regex = /^([^_-])((?!_-)(?!__)(?!--)(?!-_)[a-zA-Z0-9-_]){2,18}([^_-])$/;
    if(!regex.test(username)) {
        return res.status(statusCodes.invalidCredentials).json({
            message: responseMessages.failure,
            message: "Choose a different username"
        });
    }

    db.query("SELECT COUNT(*) AS is_there FROM users WHERE UPPER(username) = UPPER(?)", [username], 
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        }
        if (result[0].is_there > 0) {
            return res.status(statusCodes.alreadyExists).json({
                status: responseMessages.failure,
                message: "Choose a different username"
            });
        } else {
            return res.status(statusCodes.success).json({
                status: responseMessages.success,
                message: "Username is available"
            });
        }
    });
});

app.post("/edify/user/check-email", async (req, res) => {
    const {email} = req.body;

    if(!email) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    const domain = email.split("@")[1].split(".")[0];
    const filterList = ["gmail", "yahoo", "rediffmail", "rediff", "icloud", "hotmail", "outlook"];
    if(filterList.includes(domain)) {
        return res.status(statusCodes.invalidCredentials).json({
            response: responseMessages.failure,
            message: "Public domain email addresses are not allowed"
        });
    } else {
        db.query("SELECT COUNT(*) AS is_there FROM users WHERE UPPER(email) = UPPER(?)", [email], 
        (err, result) => {
            if(err) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: responseMessages.databaseError,
                    error_message: err.message
                });
            }
            if (result[0].is_there > 0) {
                return res.status(statusCodes.alreadyExists).json({
                    status: responseMessages.failure,
                    message: "Account with this email address already exists"
                });
            } else {
                return res.status(statusCodes.success).json({
                    status: responseMessages.success,
                    message: "Email address is available"
                });
            }
        });
    }
});

app.post("/edify/user/register", (req, res) => {
    const {username, email, password} = req.body;
    
    if(!username || !email || !password) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    const domain = email.split("@")[1];
    const encryptedPassword = aes256.encrypt(process.env.PASSWORD_ENCRYPTION_KEY, password);
    db.query("INSERT INTO users (username, email, password, company_domain) VALUE (?, ?, ?, ?)", 
    [username, email, encryptedPassword, domain],
    async (err) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            try {
                const token = jwt.sign({username, email}, process.env.JWT_USER_REGISTRATION, {expiresIn: process.env.USER_REGISTRATION_EXPIRY});
                const url = `${process.env.FRONTEND_ENTER_USER_DETAILS_URL}?token=${token}`;
                await transporter.sendMail({
                    from: "Survey Team <" + process.env.SENDER_GMAIL + ">",
                    to: email,
                    subject: emailTemplates.activateUserAccount.subject,
                    html: emailTemplates.activateUserAccount.html.replace("{{link to frontend enter details}}", url),
                });
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Account created successfully",
                    token
                });
            } catch (err) {
                return res.status(statusCodes.errorInSendingEmail).json({
                    response: responseMessages.failure,
                    message: responseMessages.errorInSendingEmail,
                    error_message: err.message
                });
            }
        }
    });
});

app.post("/edify/user/enter-details", (req, res) => {
    const {token} = req.query;
    const {name, mob_no, company_name} = req.body;

    if(!token || !name || !mob_no || !company_name) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    const country_prefix = mob_no.split(" ")[0];
    const mobile_number = mob_no.substring(country_prefix.length + 1);
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_USER_REGISTRATION);
        const {username, email} = decoded;
        const refresh_token = jwt.sign({email}, process.env.JWT_USER_REFRESH_TOKEN, {expiresIn: process.env.USER_REFRESH_TOKEN_EXPIRY});
        const encrypted_refresh_token = aes256.encrypt(process.env.USER_REFRESH_TOKEN_ENCRYPTION_KEY, refresh_token);
        const access_token = jwt.sign({username, refresh_token: encrypted_refresh_token}, process.env.JWT_USER_ACCESS_TOKEN, {expiresIn: process.env.USER_ACCESS_TOKEN_EXPIRY});
        db.query("UPDATE users SET name = ?, country_prefix = ?, mob_no = ?, company_name = ?, refresh_token = ?, active_flag = 1 WHERE username = ? AND email = ? AND active_flag = 0", 
        [name, country_prefix, mobile_number, company_name, refresh_token, username, email],
        (err, result) => {
            if(err) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: responseMessages.databaseError,
                    error_message: err.message
                });
            } else {
                if(result.changedRows === 0) {
                    return res.status(statusCodes.alreadyExists).json({
                        response: responseMessages.failure,
                        message: "User already registered"
                    });
                } else {
                    return res.status(statusCodes.success).json({
                        response: responseMessages.success,
                        message: "User registration successful",
                        access_token,
                        refresh_token
                    });
                }
            }
        });
    } catch (err) {
        return res.status(statusCodes.invalidToken).json({
            response: responseMessages.failure,
            message: responseMessages.invalidToken,
            error_message: err.message
        });
    }
});

app.post("/edify/user/login", (req, res) => {
    const {email_or_username, password} = req.body;

    if(!email_or_username || !password) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    db.query("SELECT active_flag, email, username, password, admin_token FROM users WHERE email = ? OR username = ?", 
    [email_or_username, email_or_username],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0 || aes256.decrypt(process.env.PASSWORD_ENCRYPTION_KEY, result[0].password) !== password) {
                return res.status(statusCodes.invalidCredentials).json({
                    response: responseMessages.failure,
                    message: "Invalid Credentials"
                });
            } else {
                if(result[0].active_flag === 0) {
                    return res.status(statusCodes.userNotRegistered).json({
                        response: responseMessages.failure,
                        message: "User Account Not Activated"
                    });
                } else {
                    const {email, username} = result[0];
                    const refresh_token = jwt.sign({email}, process.env.JWT_USER_REFRESH_TOKEN, {expiresIn: process.env.USER_REFRESH_TOKEN_EXPIRY});
                    const encrypted_refresh_token = aes256.encrypt(process.env.USER_REFRESH_TOKEN_ENCRYPTION_KEY, refresh_token);
                    const access_token = jwt.sign({username, refresh_token: encrypted_refresh_token}, process.env.JWT_USER_ACCESS_TOKEN, {expiresIn: process.env.USER_ACCESS_TOKEN_EXPIRY});
                    db.query("UPDATE users SET refresh_token = ? WHERE email = ?", [refresh_token, email], (err) => {
                        if(err) {
                            console.log(err);
                            return res.status(statusCodes.databaseError).json({
                                response: responseMessages.failure,
                                message: responseMessages.databaseError,
                                error_message: err.message
                            });
                        } else {
                            return res.status(statusCodes.success).json({
                                response: responseMessages.success,
                                message: "Login successful",
                                access_token,
                                refresh_token,
                                admin_token: result[0].admin_token !== null ? result[0].admin_token : undefined
                            });
                        }
                    });
                }
            }
        }
    });
});

app.post("/edify/user/forgot-password", (req, res) => {
    const {email_or_username} = req.body;

    if(!email_or_username) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    db.query("SELECT email, password FROM users WHERE email = ? OR username = ?", 
    [email_or_username, email_or_username],
    async (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "User Not Found"
                });
            } else {
                const {email, password} = result[0];
                const decrypted_password = aes256.decrypt(process.env.PASSWORD_ENCRYPTION_KEY, password);
                const encrypted_password = aes256.encrypt(process.env.PASSWORD_RESET_ENCRYPTION_KEY, decrypted_password);
                const token = jwt.sign({email, password: encrypted_password}, process.env.JWT_USER_FORGOT_PASSWORD, {expiresIn: process.env.USER_FORGOT_PASSWORD_EXPIRY});
                const url = `${process.env.FRONTEND_NEW_PASSWORD_URL}?token=${token}`;
                console.log(url);
                try {
                    await transporter.sendMail({
                        from: "Survey Team <" + process.env.SENDER_GMAIL + ">",
                        to: email,
                        subject: emailTemplates.resetUserPassword.subject,
                        html: emailTemplates.resetUserPassword.html.replace("{{link to frontend password reset}}", url)
                    });
                    return res.status(statusCodes.success).json({
                        response: responseMessages.success,
                        message: "Reset password link sent to your email",
                        token
                    });
                } catch (err) {
                    return res.status(statusCodes.errorInSendingEmail).json({
                        response: responseMessages.failure,
                        message: responseMessages.errorInSendingEmail,
                        error_message: err.message
                    });
                }
            }
        }
    });
});

app.post("/edify/user/new-password", (req, res) => {
    const {token} = req.query;
    const {new_password} = req.body;

    if(!token || !new_password) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    try {
        const {email, password} = jwt.verify(token, process.env.JWT_USER_FORGOT_PASSWORD);
        const decrypted_password = aes256.decrypt(process.env.PASSWORD_RESET_ENCRYPTION_KEY, password);
        if(decrypted_password === new_password) {
            return res.status(statusCodes.invalidCredentials).json({
                response: responseMessages.failure,
                message: "Old Password and New Password cannot be same"
            });
        } else {
            const encrypted_password = aes256.encrypt(process.env.PASSWORD_ENCRYPTION_KEY, new_password);
            db.query("SELECT password FROM users WHERE email = ?", [email],
            (err, result) => {
                if(err) {
                    console.log(err);
                    return res.status(statusCodes.databaseError).json({
                        response: responseMessages.failure,
                        message: responseMessages.databaseError,
                        error_message: err.message
                    });
                } else {
                    if(result.length === 0) {
                        return res.status(statusCodes.noSuchResource).json({
                            response: responseMessages.failure,
                            message: "User Not Found"
                        });
                    } else {
                        if(aes256.decrypt(process.env.PASSWORD_ENCRYPTION_KEY, result[0].password) !== decrypted_password) {
                            return res.status(statusCodes.accessDenied).json({
                                response: responseMessages.failure,
                                message: responseMessages.accessDenied
                            });
                        } else {
                            db.query("UPDATE users SET password = ? WHERE email = ?", [encrypted_password, email], 
                            (err) => {
                                if(err) {
                                    console.log(err);
                                    return res.status(statusCodes.databaseError).json({
                                        response: responseMessages.failure,
                                        message: responseMessages.databaseError,
                                        error_message: err.message
                                    });
                                } else {
                                    return res.status(statusCodes.success).json({
                                        response: responseMessages.success,
                                        message: "Password Reset Successfully"
                                    });
                                }
                            });
                        }
                    }
                }
            });
        }
    } catch (err) {
        return res.status(statusCodes.invalidToken).json({
            response: responseMessages.failure,
            message: responseMessages.invalidToken,
            error_message: err.message
        });
    }
});

app.post("/edify/user/change-password", checkUserAccess, (req, res) => {
    const {old_password, new_password, username, email} = req.body;

    if(!old_password || !new_password) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    const refresh_token = jwt.sign({email}, process.env.JWT_USER_REFRESH_TOKEN, {expiresIn: process.env.USER_REFRESH_TOKEN_EXPIRY});
    db.query("SELECT password FROM users WHERE username = ?", [username],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "User Not Found"
                });
            } else {
                const decrypted_password = aes256.decrypt(process.env.PASSWORD_ENCRYPTION_KEY, result[0].password);
                if(decrypted_password !== old_password) {
                    return res.status(statusCodes.invalidCredentials).json({
                        response: responseMessages.failure,
                        message: responseMessages.invalidCredentials
                    });
                } else {
                    const encrypted_password = aes256.encrypt(process.env.PASSWORD_ENCRYPTION_KEY, new_password);
                    db.query("UPDATE users SET password = ?, refresh_token = ? WHERE username = ?", 
                    [encrypted_password, refresh_token, username], 
                    (err) => {
                        if(err) {
                            console.log(err);
                            return res.status(statusCodes.databaseError).json({
                                response: responseMessages.failure,
                                message: responseMessages.databaseError,
                                error_message: err.message
                            });
                        } else {
                            return res.status(statusCodes.success).json({
                                response: responseMessages.success,
                                message: "Password Changed Successfully. Please login again"
                            });
                        }
                    });
                }
            }
        }
    });
});

// app.get("/edify/user/get-section-names", (req, res) => {
//     db.query("SELECT section_name FROM questions GROUP BY section_name",
//     (err, result) => {
//         if(err) {
//             console.log(err);
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: err.message
//             });
//         } else {
//             if(result.length === 0) {
//                 return res.status(statusCodes.noSuchResource).json({
//                     response: responseMessages.failure,
//                     message: "No questions in the database"
//                 });
//             } else {
//                 let section_names = [];
//                 result.forEach((section) => {
//                     section_names.push(section.section_name);
//                 });
//                 return res.status(statusCodes.success).json({
//                     response: responseMessages.success,
//                     message: "Section Names Fetched Successfully",
//                     section_names
//                 });
//             }
//         }
//     });
// });

// app.get("/edify/user/get-section-details", (req, res) => {
//     const {section_name} = req.query;

//     if(!section_name) {
//         return res.status(statusCodes.insufficientData).json({
//             response: responseMessages.failure, 
//             message: responseMessages.insufficientData
//         });
//     }

//     db.query("SELECT subsection_name FROM questions WHERE section_name = ? GROUP BY subsection_name", [section_name],
//     (err, result) => {
//         if(err) {
//             console.log(err);
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: err.message
//             });
//         } else {
//             if(result.length === 0) {
//                 return res.status(statusCodes.noSuchResource).json({
//                     response: responseMessages.failure,
//                     message: "No questions for the section in the database"
//                 });
//             } else if(result.length === 1 && result[0].subsection_name === null) {
//                 db.query("SELECT id FROM questions WHERE section_name = ? ORDER BY section_name ASC, subsection_name ASC, question_number ASC", [section_name],
//                 (err, result) => {
//                     if(err) {
//                         console.log(err);
//                         return res.status(statusCodes.databaseError).json({
//                             response: responseMessages.failure,
//                             message: responseMessages.databaseError,
//                             error_message: err.message
//                         });
//                     } else {
//                         if(result.length === 0) {
//                             return res.status(statusCodes.noSuchResource).json({
//                                 response: responseMessages.failure,
//                                 message: "No questions in the database"
//                             });
//                         } else {
//                             let question_ids = [];
//                             result.forEach((question) => {
//                                 question_ids.push(question.id);
//                             });
//                             return res.status(statusCodes.success).json({
//                                 response: responseMessages.success,
//                                 message: "Question ids Fetched Successfully",
//                                 question_ids
//                             });
//                         }
//                     }
//                 });
//             } else {
//                 let subsection_names = [];
//                 result.forEach((subsection) => {
//                     subsection_names.push(subsection.subsection_name);
//                 });
//                 return res.status(statusCodes.success).json({
//                     response: responseMessages.success,
//                     message: "Sub Section Names Fetched Successfully",
//                     subsection_names
//                 });
//             }
//         }
//     });
// });

// app.get("/edify/user/get-subsection-details", (req, res) => {
//     const {section_name, subsection_name} = req.query;

//     if(!section_name || !subsection_name) {
//         return res.status(statusCodes.insufficientData).json({
//             response: responseMessages.failure, 
//             message: responseMessages.insufficientData
//         });
//     }

//     db.query("SELECT id FROM questions WHERE section_name = ? AND subsection_name = ? ORDER BY section_name ASC, subsection_name ASC, question_number ASC", 
//     [section_name, subsection_name],
//     (err, result) => {
//         if(err) {
//             console.log(err);
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: err.message
//             });
//         } else {
//             if(result.length === 0) {
//                 return res.status(statusCodes.noSuchResource).json({
//                     response: responseMessages.failure,
//                     message: "No questions in the database"
//                 });
//             } else {
//                 let question_ids = [];
//                 result.forEach((question) => {
//                     question_ids.push(question.id);
//                 });
//                 return res.status(statusCodes.success).json({
//                     response: responseMessages.success,
//                     message: "Question ids Fetched Successfully",
//                     question_ids
//                 });
//             }
//         }
//     });
// });

// app.get("/edify/user/get-question", (req, res) => {
//     const {question_id} = req.query;

//     if(!question_id) {
//         return res.status(statusCodes.insufficientData).json({
//             response: responseMessages.failure, 
//             message: responseMessages.insufficientData
//         });
//     }

//     db.query("SELECT section_name, subsection_name, question_description, choice_details, question_help, created_on, created_by, updated_on, updated_by FROM questions WHERE id = ?", 
//     [question_id],
//     (err, result) => {
//         if(err) {
//             console.log(err);
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: err.message
//             });
//         } else {
//             if(result.length === 0) {
//                 return res.status(statusCodes.noSuchResource).json({
//                     response: responseMessages.failure,
//                     message: "Question not found"
//                 });
//             } else {
//                 result[0].choice_details = JSON.parse(result[0].choice_details);
//                 result[0].subsection_name = result[0].subsection_name === null ? "" : result[0].subsection_name;
//                 result[0].question_help = result[0].question_help === null ? "" : result[0].question_help;
//                 result[0].created_on = new Date(result[0].created_on).toLocaleString();
//                 result[0].updated_on = result[0].updated_on === null ? "" : new Date(result[0].updated_on).toLocaleString();
//                 result[0].updated_by = result[0].updated_by === null ? "" : result[0].updated_by;
//                 return res.status(statusCodes.success).json({
//                     response: responseMessages.success,
//                     message: "Question details Fetched Successfully",
//                     question_details: result[0]
//                 });
//             }
//         }
//     });
// });

app.get("/edify/user/get-all-questions", (req, res) => {
    db.query("SELECT id, section_name, subsection_name, question_number, question_description, choice_details, question_help, created_on, created_by, updated_on, updated_by FROM current_questions ORDER BY section_name ASC, question_number ASC", 
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "No questions in the database"
                });
            } else {
                result.forEach((question) => {
                    question.choice_details = JSON.parse(question.choice_details);
                    question.subsection_name = question.subsection_name === null ? "" : question.subsection_name;
                    question.question_help = question.question_help === null ? "" : question.question_help;
                    question.created_on = new Date(question.created_on).toLocaleString();
                    question.updated_on = question.updated_on === null ? "" : new Date(question.updated_on).toLocaleString();
                    question.updated_by = question.updated_by === null ? "" : question.updated_by;
                });
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Question details Fetched Successfully",
                    questions: result
                });
            }
        }
    });
});

app.post("/edify/user/submit-question-batch", (req, res) => {
    const {questions} = req.body;

    const username = "admin";

    if(!questions) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    var query_part = 0;
    var error_caused = false;
    
    db.query("SELECT MAX(batch_id) AS batch_id FROM questions", 
    (err1, result1) => {
        if (err1) {
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err1.message
            });
        } else {
            const batch_id  = result1[0].batch_id + 1;
            questions.forEach((question) => {
                if(error_caused) {  return;  }
                try {
                    question.choice_details = JSON.stringify(question.choice_details);
                } catch(err) {
                    error_caused = true;
                    return res.status(statusCodes.invalidFormat).json({
                        response: responseMessages.failure, 
                        message: responseMessages.invalidFormat
                    });
                }
                if(question.id === null || question.id === undefined) {
                    query_part += `, ('${question.section_name}', '${question.subsection_name === "" ? null : question.subsection_name}', '${question.question_number}', '${question.question_description}', '${question.choice_details}', '${question.question_help === "" ? null : question.question_help}', '${username}', ${batch_id})`;
                } else {
                    db.query("UPDATE current_questions SET section_name = ?, subsection_name = ?, question_number = ?, question_description = ?, choice_details = ?, question_help = ?, updated_on = CURRENT_TIMESTAMP(), updated_by = ?, batch_id = ? WHERE id = ?",
                    [question.section_name, question.subsection_name, question.question_number, question.question_description, question.choice_details, question.question_help, username, batch_id, question.id],
                    (err, result) => {
                        if(err) {
                            console.log(err);
                            error_caused = true;
                            return res.status(statusCodes.databaseError).json({
                                response: responseMessages.failure,
                                message: responseMessages.databaseError,
                                error_message: err.message
                            });
                        } else {
                            if(result.affectedRows === 0) {
                                error_caused = true;
                                return res.status(statusCodes.noSuchResource).json({
                                    response: responseMessages.failure,
                                    message: "Question not found"
                                });
                            }
                        }
                    });
                }
            });
            db.query("DELETE FROM current_questions WHERE batch_id != ?",
            [batch_id],
            (err1) => {
                if (err1) {
                    return res.status(statusCodes.databaseError).json({
                        response: responseMessages.failure,
                        message: responseMessages.databaseError,
                        error_message: err1.message
                    });
                } else {
                    if(query_part !== 0) {
                        db.query("INSERT INTO current_questions (section_name, subsection_name, question_number, question_description, choice_details, question_help, created_by, batch_id) VALUES " + query_part.substring(2),
                        (err, result) => {
                            if(err) {
                                console.log(err);
                                return res.status(statusCodes.databaseError).json({
                                    response: responseMessages.failure,
                                    message: responseMessages.databaseError,
                                    error_message: err.message
                                });
                            } else {
                                return res.status(statusCodes.success).json({
                                    response: responseMessages.success,
                                    message: "Questions submitted successfully"
                                });
                            }
                        });
                    } else {
                        return res.status(statusCodes.success).json({
                            response: responseMessages.success,
                            message: "Questions submitted successfully"
                        });
                    }
                }
            });
        }
    });
});

// app.post("/edify/user/add-question", (req, res) => {
//     var {section_name, subsection_name, question_description, choice_details, question_help, username} = req.body;

//     subsection_name = subsection_name? subsection_name : null;
//     question_help = question_help? question_description : null;

//     if(!section_name || !question_description || !choice_details) {
//         return res.status(statusCodes.insufficientData).json({
//             response: responseMessages.failure, 
//             message: responseMessages.insufficientData
//         });
//     }

//     try {
//         choice_details = JSON.stringify(choice_details);
//     } catch(err) {
//         return res.status(statusCodes.invalidFormat).json({
//             response: responseMessages.failure, 
//             message: responseMessages.invalidFormat,
//             error_message: err.message
//         });
//     }

//     db.query("CALL get_batch_id()",
//     (err, result) => {
//         if (err || !result || !result[0] || !result[0][0]) {
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: (err)? err.message : undefined
//             });
//         } else {
//             const batch_id = result[0][0].batch_id;
//             db.query("INSERT INTO questions (section_name, subsection_name, question_description, choice_details, question_help, created_by, batch_id) VALUE (?, ?, ?, ?, ?, ?, ?)", 
//             [section_name, subsection_name, question_description, choice_details, question_help, username, batch_id],
//             (err1, result1) => {
//             if (err1 || result.affectedRows === 0) {
//                 return res.status(statusCodes.databaseError).json({
//                     response: responseMessages.failure,
//                     message: responseMessages.databaseError,
//                     error_message: (err1)? err1.message : undefined
//                 });
//             } else {
//                 return res.status(statusCodes.success).json({
//                     response: responseMessages.success,
//                     message: "Question Added Successfully",
//                     new_ques_id: result1.insertId
//                 });
//             }
//     });
//         }
//     })
// });

// app.patch("/edify/user/update-question", (req, res) => {
//     var {question_id} = req.query;
//     var {section_name, subsection_name, question_description, choice_details, question_help, username} = req.body;

//     subsection_name = subsection_name? null : subsection_name;
//     question_help = question_help? null : question_help;

//     if(!question_id || !section_name || !question_description || !choice_details) {
//         return res.status(statusCodes.insufficientData).json({
//             response: responseMessages.failure, 
//             message: responseMessages.insufficientData
//         });
//     }

//     try {
//         choice_details = JSON.stringify(choice_details);
//     } catch(err) {
//         return res.status(statusCodes.invalidFormat).json({
//             response: responseMessages.failure, 
//             message: responseMessages.invalidFormat,
//             error_message: err.message
//         });
//     }

//     db.query("CALL update_question(?, ?, ?, ?, ?, ?, ?)", [question_id, section_name, subsection_name, question_description, choice_details, question_help, username],
//     (err, result) => {
//         if (err || !result || !result[0] || !result[0][0]) {
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: (err)? err.message : undefined
//             });
//         } else {
//             if(result[0][0].status === -1) {
//                 return res.status(statusCodes.noSuchResource).json({
//                     response: responseMessages.failure,
//                     message: "Question not found"
//                 });
//             } else {
//                 return res.status(statusCodes.success).json({
//                     response: responseMessages.success,
//                     message: "Question Updated Successfully",
//                     new_ques_id: result[0][0].id
//                 });
//             }
//         }
//     });
// });

// app.delete("/edify/user/delete-question", (req, res) => {
//     const {question_id} = req.query;

//     if(!question_id) {
//         return res.status(statusCodes.insufficientData).json({
//             response: responseMessages.failure, 
//             message: responseMessages.insufficientData
//         });
//     }

//     db.query("CALL delete_question(?)", 
//     [question_id],
//     (err, result) => {
//         if (err || !result || !result[0] || !result[0][0]) {
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: (err)? err.message : undefined
//             });
//         } else {
//             if(result[0][0].status === -1) {
//                 return res.status(statusCodes.noSuchResource).json({
//                     response: responseMessages.failure,
//                     message: "Question not found"
//                 });
//             } else {
//                 return res.status(statusCodes.success).json({
//                     response: responseMessages.success,
//                     message: "Question Deleted Successfully"
//                 });
//             }
//         }
//     });
// });

// app.get("/edify/user/get-questions", (req, res) => {
//     db.query("CALL get_batch_id()",
//     (err, result) => {
//         if(err) {
//             console.log(err);
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: err.message
//             });
//         } else {
//             const batch_id = result[0][0].batch_id;
//             db.query("SELECT section_name, subsection_name, question_description, choice_details, question_help, created_on, created_by, updated_on, updated_by FROM questions WHERE compatibility_till > ? ORDER BY section_name ASC, subsection_name ASC, question_number ASC", [batch_id],
//             (err1, result1) => {
//                 if (err1) {
//                     return res.status(statusCodes.databaseError).json({
//                         response: responseMessages.failure,
//                         message: responseMessages.databaseError,
//                         error_message: err1.message
//                     });
//                 } else {
//                     if(result1.length === 0) {
//                         return res.status(statusCodes.noSuchResource).json({
//                             response: responseMessages.failure,
//                             message: "No questions found"
//                         });
//                     } else {
//                         result1.forEach((question) => {
//                             question.choice_details = JSON.parse(question.choice_details);
//                             question.subsection_name = question.subsection_name === null ? "" : question.subsection_name;
//                             question.question_help = question.question_help === null ? "" : question.question_help;
//                             question.created_on = question.created_on === null ? "" : new Date(question.created_on).toLocaleString();
//                             question.updated_on = question.updated_on === null ? "" : new Date(question.updated_on).toLocaleString();
//                             question.updated_by = question.updated_by === null ? "" : question.updated_by;
//                         });
//                         return res.status(statusCodes.success).json({
//                             response: responseMessages.success,
//                             message: "Questions Fetched Successfully",
//                             questions: result1
//                         });
//                     }
//                 }
//             });
//         }
//     });
// });

// app.get("/edify/user/enable-batch", (req, res) => {
//     db.query("CALL get_batch_id()",
//     (err, result) => {
//         if (err || !result || !result[0] || !result[0][0]) {
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: (err)? err.message : undefined
//             });
//         } else {
//             const batch_id = result[0][0].batch_id;
//             db.query("UPDATE questions SET is_enabled = 1 WHERE batch_id = ?", [batch_id],
//             (err1) => {
//                 if (err1) {
//                     return res.status(statusCodes.databaseError).json({
//                         response: responseMessages.failure,
//                         message: responseMessages.databaseError,
//                         error_message: err1.message
//                     });
//                 } else {
//                     return res.status(statusCodes.success).json({
//                         response: responseMessages.success,
//                         message: "Questions Enabled Successfully"
//                     });
//                 }
//             });
//         }
//     })
// });

app.post("/edify/customer/enter-email", (req, res) => {
    const {email} = req.body;

    if(!email) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    db.query("SELECT COUNT(*) AS 'already_exists' FROM customers WHERE company_email_id = ?", [email],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            db.query("INSERT INTO customer_otp (email, otp) VALUE (?, ?)", [email, otp],
            async (err1, result1) => {
                if (err1) {
                    return res.status(statusCodes.databaseError).json({
                        response: responseMessages.failure,
                        message: responseMessages.databaseError,
                        error_message: err1.message
                    });
                } else {
                    var subject, text;
                    var status, responseMessage;
                    if(result[0].already_exists !== 0) {
                        subject = emailTemplates.customerLogin.subject;
                        text = emailTemplates.customerLogin.text.replace("{{otp}}", otp);
                        status = statusCodes.success;
                        responseMessage = "OTP for login sent to your email";
                    } else {
                        subject = emailTemplates.customerRegistration.subject;
                        text = emailTemplates.customerRegistration.text.replace("{{otp}}", otp);
                        status = statusCodes.resourceCreated;
                        responseMessage = "OTP for registration sent to your email";
                    }
                    try {
                        await transporter.sendMail({
                            from: "Survey Team <" + process.env.SENDER_GMAIL + ">",
                            to: email,
                            subject: subject,
                            text: text
                        });
                    }
                    catch(err) {
                        console.log(err);
                        return res.status(statusCodes.errorInSendingEmail).json({
                            response: responseMessages.failure,
                            message: responseMessages.errorInSendingEmail,
                            error_message: err.message
                        });
                    }
                    return res.status(status).json({
                        response: responseMessages.success,
                        message: responseMessage
                    });
                }
            })
        }
    });
});

app.post("/edify/customer/verify-otp", (req, res) => {
    const {email, otp} = req.body;

    if(!email || !otp) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    db.query("SELECT COUNT(*) FROM customer_otp WHERE email = ? AND otp = ?", [email, otp],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length > 0 || otp === "000000") {
                db.query("SELECT customer_id, customer_name FROM customers WHERE company_email_id = ?", [email],
                (err1, result1) => {
                    if(err1) {
                        console.log(err1);
                        return res.status(statusCodes.databaseError).json({
                            response: responseMessages.failure,
                            message: responseMessages.databaseError,
                            error_message: err1.message
                        });
                    } else {
                        const refresh_token = jwt.sign({email: email}, process.env.JWT_CUSTOMER_REFRESH_TOKEN, {expiresIn: process.env.CUSTOMER_REFRESH_TOKEN_EXPIRY});
                        const encrypted_refresh =  aes256.encrypt(process.env.CUSTOMER_REFRESH_TOKEN_ENCRYPTION_KEY, refresh_token); 
                        var customer_id = (result1.length > 0)? result1[0].customer_id : uuidv4();
                        const access_token = jwt.sign({refresh_token: encrypted_refresh, customer_id: customer_id, email: email}, process.env.JWT_CUSTOMER_ACCESS_TOKEN, {expiresIn: process.env.CUSTOMER_ACCESS_TOKEN_EXPIRY});
                        if(result1.length > 0) {
                            db.query("UPDATE customers SET refresh_token = ? WHERE company_email_id = ?", [refresh_token, email],
                            (err2, result2) => {
                                console.log(err2);
                                if(err2) {
                                    return res.status(statusCodes.databaseError).json({
                                        response: responseMessages.failure,
                                        message: responseMessages.databaseError,
                                        error_message: err2.message
                                    });
                                } else {
                                    return res.status(statusCodes.success).json({
                                        response: responseMessages.success,
                                        message: "OTP Verified",
                                        access_token,
                                        refresh_token
                                    });
                                }
                            });
                        } else {
                            db.query("INSERT INTO customers (customer_id, company_email_id, refresh_token, batch_id) VALUE(?, ?, ?, 1)", 
                            [customer_id, email, refresh_token],
                            (err2, result2) => {
                                console.log(err2);
                                if(err2) {
                                    return res.status(statusCodes.databaseError).json({
                                        response: responseMessages.failure,
                                        message: responseMessages.databaseError,
                                        error_message: err2.message
                                    });
                                } else {
                                    return res.status(statusCodes.success).json({
                                        response: responseMessages.success,
                                        message: "OTP Verified",
                                        access_token,
                                        refresh_token
                                    });
                                }
                            });
                        }
                    }
                });
            } else {
                return res.status(statusCodes.invalidCredentials).json({
                    response: responseMessages.failure,
                    message: "Invalid Credentials"
                });
            }
        }
    });
});

app.get("/edify/customer/generate-access-token", checkCustomerAccess, (req, res) => {
    const {refresh_token, email, customer_id} = req.body;
    const encrypted_refresh =  aes256.encrypt(process.env.CUSTOMER_REFRESH_TOKEN_ENCRYPTION_KEY, refresh_token); 
    const access_token = jwt.sign({refresh_token: encrypted_refresh, customer_id: customer_id}, process.env.JWT_CUSTOMER_ACCESS_TOKEN, {expiresIn: process.env.CUSTOMER_ACCESS_TOKEN_EXPIRY});
    return res.status(statusCodes.success).json({
        response: responseMessages.success,
        message: "Access Token Generation Successful", 
        access_token
    });
});

app.get("/edify/customer/get-nav-data", checkCustomerAccess, (req, res) => {
    const {customer_id} = req.body;

    db.query("SELECT current_question, current_section, survey_complete_flag FROM survey_answers WHERE customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {  
            db.query("SELECT batch_id FROM customers WHERE customer_id = ?", [customer_id],
            (err1, result1) => {
                if(err1) {
                    console.log(err1);
                    return res.status(statusCodes.databaseError).json({
                        response: responseMessages.failure,
                        message: responseMessages.databaseError,
                        error_message: err1.message
                    });
                } else {
                    if(result1.length > 0) {
                        db.query("SELECT id FROM questions WHERE batch_id = ? ORDER BY section_name ASC, question_number ASC", 
                        [result1[0].batch_id],
                        (err2, result2) => {
                            if(err2) {
                                console.log(err2);
                                return res.status(statusCodes.databaseError).json({
                                    response: responseMessages.failure,
                                    message: responseMessages.databaseError,
                                    error_message: err2.message
                                });
                            } else {
                                var question_ids = [];
                                result2.forEach((question) => {
                                    question_ids.push(question.id);
                                });
                                const current_section = (result.length > 0)? (result[0].survey_complete_flag === 1)? "SurveyComplete" : result[0].current_section : "BasicDetails";
                                const current_question = (result.length > 0)? (result[0].survey_complete_flag === 1)? question_ids[question_ids.length-1] : result[0].current_question : question_ids[0];
                                return res.status(statusCodes.success).json({
                                    response: responseMessages.success,
                                    message: "Nav Data Fetched", 
                                    current_section,
                                    current_question,
                                    no_of_questions: question_ids.length,
                                    question_ids
                                });
                            }
                        });
                    } else {
                        return res.status(statusCodes.noSuchResource).json({
                            response: responseMessages.failure,
                            message: "Customer Not Found"
                        });
                    }
                }
            });
        }
    });
});

app.get("/edify/customer/get-details", checkCustomerAccess, (req, res) => {
    const {customer_id} = req.body;

    db.query("SELECT customer_name, company_name, company_url, designation, company_email_id, mobile_no, country FROM customers WHERE customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "Customer Not Found"
                });
            } else {
                result[0].company_url = (result[0].company_url === null)? "" : result[0].company_url;
                result[0].designation = (result[0].designation === null)? "" : result[0].designation;
                result[0].mobile_no = (result[0].mobile_no === null)? "" : result[0].mobile_no;
                result[0].country = (result[0].country === null)? "" : result[0].country;
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "User Details Fetched", 
                    user_details: result[0]
                });
            }
        }
    });
});

app.post("/edify/customer/enter-details", checkCustomerAccess, (req, res) => {
    var {customer_name, company_name, mobile_no, customer_id, designation, country, company_url} = req.body;
    designation = designation || null;
    country = country || null;
    company_url = company_url || null;

    if(!customer_name || !company_name || !mobile_no) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure, 
            message: responseMessages.insufficientData
        });
    }

    db.query("SELECT registration_status FROM customers WHERE customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "Customer Not Found"
                });
            } else {
                if(result[0].registration_status === 1) {
                    return res.status(statusCodes.alreadyExists).json({
                        response: responseMessages.failure,
                        message: "Customer already registered"
                    });
                } else {
                    db.query("UPDATE customers SET customer_name = ?, mobile_no = ?, company_name = ?, designation = ?, country = ?, company_url = ?, registration_status = 1 WHERE customer_id = ?",
                    [customer_name, mobile_no, company_name, designation, country, company_url, customer_id],
                    (err1, result1) => {
                        if(err1) {
                            return res.status(statusCodes.databaseError).json({
                                response: responseMessages.failure,
                                message: responseMessages.databaseError,
                                error_message: err1.message
                            });
                        } else {
                            // const link = process.env.ROUTE_TO_START;
                            // try {
                            // await transporter.sendMail({
                            //     from: "Survey Team <" + process.env.SENDER_GMAIL + ">",
                            //     to: email,
                            //     subject: emailTemplates.customerSurveyStart.subject,
                            //     html: emailTemplates.customerSurveyStart.html.replace("{{customer_name}}", customer_name).replace("{{link}}", link)
                            // });
                            return res.status(statusCodes.success).json({
                                response: responseMessages.success,
                                message: "Details Registered"
                            });
                            // }
                            // catch(err) {
                            //     console.log(err);
                            //     return res.status(statusCodes.errorInSendingEmail).json({
                            //         response: responseMessages.failure,
                            //         message: responseMessages.errorInSendingEmail,
                            //         error_message: err.message
                            //     });
                            // }
                        }
                    })
                }
            }
        }
    });
});

app.patch("/edify/customer/update-details", checkCustomerAccess, (req, res) => {
    var {customer_name, company_name, mobile_no, customer_id, designation, country, company_url} = req.body;
    if(!customer_name || !company_name || !mobile_no || !designation || !country || !company_url) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    db.query("UPDATE customers SET customer_name = ?, company_name = ?, mobile_no = ?, designation = ?, country = ?, company_url = ? WHERE customer_id = ?",
    [customer_name, company_name, mobile_no, designation, country, company_url, customer_id],
    (err) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "Details Updated"
            });
        }
    });
});

app.get("/edify/customer/get-question", checkCustomerAccess, (req, res) => {
    const {ques_id} = req.query;
    const {customer_id} = req.body;

    db.query("SELECT id, section_name, subsection_name, question_number, question_description, choice_details, question_help FROM questions WHERE id = ?", [ques_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length == 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "Question Not Found"
                });
            } else {
                db.query("SELECT survey_answers FROM survey_answers WHERE customer_id = ?", [customer_id],
                (err1, result1) => {
                    if(err1) {
                        console.log(err1);
                        return res.status(statusCodes.databaseError).json({
                            response: responseMessages.failure,
                            message: responseMessages.databaseError,
                            error_message: err1.message
                        });
                    } else {
                        var user_response = "";
                        if(result1.length !== 0) {
                            var survey_answers = JSON.parse(result1[0].survey_answers);
                            user_response = survey_answers[ques_id] || "";
                        }
                        return res.status(statusCodes.success).json({
                            response: responseMessages.success,
                            message: "Question Fetched",
                            question_data: {
                                ques_id: result[0].id,
                                section_name: result[0].section_name,
                                subsection_name: result[0].subsection_name === "null" ? "" : result[0].subsection_name,
                                question_number: result[0].question_number,
                                question_description: result[0].question_description,
                                choice_details: JSON.parse(result[0].choice_details),
                                question_help: result[0].question_help === null ? "" : result[0].question_help,
                                user_response
                            }
                        });
                    }
                });
                
            }
        }
    });
});

app.get("/edify/customer/all-questions", checkCustomerAccess, (req, res) => {
    const {customer_id} = req.body;
    
    db.query("SELECT batch_id FROM customers WHERE customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            db.query("SELECT id, section_name, subsection_name, question_number, question_description, choice_details, question_help FROM questions WHERE batch_id = ? ORDER BY section_name ASC, question_number ASC",
            [result[0].batch_id],
            (err1, result1) => {
                if(err1) {
                    console.log(err1);
                    return res.status(statusCodes.databaseError).json({
                        response: responseMessages.failure,
                        message: responseMessages.databaseError,
                        error_message: err1.message
                    });
                } else {
                    if(result1.length == 0) {
                        return res.status(statusCodes.noSuchResource).json({
                            response: responseMessages.failure,
                            message: "No Questions Found"
                        });
                    } else {
                        var question_data = [];
                        result1.forEach((ques) => {
                            question_data.push({
                                ques_id: ques.id,
                                section_name: ques.section_name,
                                subsection_name: ques.subsection_name !== null? ques.sub_section_name: "",
                                question_number: ques.question_number,
                                question_description: ques.question_description,
                                choice_details: JSON.parse(ques.choice_details),
                                question_help: ques.question_help !== null? ques.question_help: ""
                            });
                        });
                        return res.status(statusCodes.success).json({
                            response: responseMessages.success,
                            message: "Questions Fetched",
                            question_data
                        });
                    }
                }
            });
        }
    });
});

app.get("/edify/customer/get-current-answers", checkCustomerAccess, (req, res) => {
    const {customer_id} = req.body;

    db.query("SELECT survey_answers, current_question, current_section, max_progress FROM survey_answers WHERE customer_id = ?", 
    [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length > 0) {
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Survey Answers Fetched",
                    survey_answers: JSON.parse(result[0].survey_answers),
                    current_question: result[0].current_question,
                    current_section: result[0].current_section,
                    max_progress: result[0].max_progress
                });
            } else {
                db.query("SELECT batch_id FROM customers WHERE customer_id = ?", [customer_id],
                (err1, result1) => {
                    if(err1) {
                        console.log(err1);
                        return res.status(statusCodes.databaseError).json({
                            response: responseMessages.failure,
                            message: responseMessages.databaseError,
                            error_message: err1.message
                        });
                    } else {
                        db.query("SELECT id FROM questions WHERE batch_id = ? ORDER BY section_name ASC, question_number ASC",
                        [result1[0].batch_id, result1[0].batch_id],
                        (err2, result2) => {
                            if(err2) {
                                console.log(err2);
                                return res.status(statusCodes.databaseError).json({
                                    response: responseMessages.failure,
                                    message: responseMessages.databaseError,
                                    error_message: err2.message
                                });
                            } else {
                                if(result2.length == 0) {
                                    return res.status(statusCodes.noSuchResource).json({
                                        response: responseMessages.failure,
                                        message: "No Questions Found"
                                    });
                                } else {
                                    var survey_answers = {};
                                    result2.forEach((ques) => {
                                        survey_answers[ques.id] = {
                                            user_choice: "",
                                            user_comment: ""
                                        };
                                    });
                                    return res.status(statusCodes.success).json({
                                        response: responseMessages.success,
                                        message: "Survey Answers Fetched",
                                        survey_answers,
                                        current_question: result2[0].id,
                                        max_progress: result2[0].id,
                                        current_section: "BasicDetails"
                                    });
                                }
                            }
                        });
                    }
                });
            }
        }
    });
});

app.post("/edify/customer/submit-survey-answers", checkCustomerAccess, (req, res) => {
    var {customer_id, survey_answers, is_complete, current_ques_number, current_section} = req.body;

    if(!survey_answers || is_complete === undefined || current_ques_number === undefined || !current_section) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    var db_survey_answers;
    try {
        db_survey_answers = JSON.stringify(survey_answers);
    } catch(err) {
        return res.status(statusCodes.invalidFormat).json({
            response: responseMessages.failure, 
            message: responseMessages.invalidFormat,
            error_message: err.message
        });
    }

    db.query("SELECT COUNT(*) AS is_there FROM survey_answers WHERE customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result[0].is_there !== 0) {
                db.query("UPDATE survey_answers SET survey_answers = ?, current_question = ?, current_section = ?, survey_end_date = "+((is_complete)? "CURRENT_TIMESTAMP()": "NULL")+", survey_complete_flag = ?, latest_update_date = CURRENT_TIMESTAMP() WHERE customer_id = ?", 
                [db_survey_answers, current_ques_number, current_section, ((is_complete)? 1 : 0), customer_id],
                (err1) => {
                    if(err1) {
                        console.log(err1);
                        return res.status(statusCodes.databaseError).json({
                            response: responseMessages.failure,
                            message: responseMessages.databaseError,
                            error_message: err1.message
                        });
                    } else {
                        const survey_status = (is_complete)? "Complete" : (current_section === "Introduction" || current_section === "BasicDetails")? "Not Started" : "Pending";
                        db.query("UPDATE customers SET survey_status = ? WHERE customer_id = ?", [survey_status, customer_id],
                        (err2) => {
                            if(err2) {
                                console.log(err2);
                                return res.status(statusCodes.databaseError).json({
                                    response: responseMessages.failure,
                                    message: responseMessages.databaseError,
                                    error_message: err2.message
                                });
                            } else {
                                return res.status(statusCodes.success).json({
                                    response: responseMessages.success,
                                    message: "Survey Answers Added"
                                });
                            }
                        });
                    }
                });
            } else {
                db.query("INSERT INTO survey_answers (customer_id, survey_answers, current_question, current_section, survey_end_date, survey_complete_flag) VALUE (?, ?, ?, ?, "+((is_complete)? "CURRENT_TIMESTAMP()": "NULL")+", ?)",
                [customer_id, db_survey_answers, current_ques_number, current_section, ((is_complete)? 1 : 0)],
                (err1) => {
                    if(err1) {
                        console.log(err1);
                        return res.status(statusCodes.databaseError).json({
                            response: responseMessages.failure,
                            message: responseMessages.databaseError,
                            error_message: err1.message
                        });
                    } else {
                        const survey_status = (is_complete)? "Complete" : (current_section === "Introduction" || current_section === "BasicDetails")? "Not Started" : "Pending";
                        db.query("UPDATE customers SET survey_status = ? WHERE customer_id = ?", [survey_status, customer_id],
                        (err2) => {
                            if(err2) {
                                console.log(err2);
                                return res.status(statusCodes.databaseError).json({
                                    response: responseMessages.failure,
                                    message: responseMessages.databaseError,
                                    error_message: err2.message
                                });
                            } else {
                                return res.status(statusCodes.success).json({
                                    response: responseMessages.success,
                                    message: "Survey Answers Added"
                                });
                            }
                        });
                    }
                });
            }
        }
    });
});

app.get("/edify/customer/get-survey-score", checkCustomerAccess, (req, res) => {
    const {customer_id} = req.body;

    db.query("SELECT sa.survey_answers AS survey_answers, c.batch_id AS batch_id FROM survey_answers sa JOIN customers c ON c.customer_id = sa.customer_id WHERE sa.customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length == 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "Customer has not started the survey"
                });
            } else {
                db.query("SELECT id, section_name, choice_details FROM questions WHERE batch_id = ? ORDER BY section_name ASC, question_number ASC", [result[0].batch_id],
                (err1, result1) => {
                    if(err1) {
                        console.log(err1);
                        return res.status(statusCodes.databaseError).json({
                            response: responseMessages.failure,
                            message: responseMessages.databaseError,
                            error_message: err1.message
                        });
                    } else {
                        var survey_answers = JSON.parse(result[0].survey_answers);
                        var score = {};
                        result1.forEach((ques) => {
                            var choices = JSON.parse(ques.choice_details);
                            if(!score[ques.section_name]) {
                                score[ques.section_name] = {
                                    score: 0,
                                    total: 0
                                };
                            } 
                            var max_rank = Number.MIN_VALUE;
                            choices.forEach((choice) => {
                                if(choice.key === survey_answers[ques.id].user_choice) {
                                    score[ques.section_name].score += choice.rank;
                                }
                                max_rank = Math.max(max_rank, choice.rank);
                            });
                            score[ques.section_name].total += max_rank;
                        });
                        return res.status(statusCodes.success).json({
                            response: responseMessages.success,
                            message: "Survey Score Fetched",
                            score
                        });
                    }
                });
            }
        }
    });
});

app.get("/edify/customer/get-survey-result", checkCustomerAccess, (req, res) => {
    const {customer_id} = req.body;

    db.query("SELECT sa.survey_answers AS survey_answers, c.batch_id AS batch_id FROM survey_answers sa JOIN customers c ON c.customer_id = sa.customer_id WHERE sa.customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length == 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "Customer has not started the survey"
                });
            } else {
                db.query("SELECT id, question_description, choice_details FROM questions WHERE batch_id = ? ORDER BY section_name ASC, question_number ASC", [result[0].batch_id],
                (err1, result1) => {
                    if(err1) {
                        console.log(err1);
                        return res.status(statusCodes.databaseError).json({
                            response: responseMessages.failure,
                            message: responseMessages.databaseError,
                            error_message: err1.message
                        });
                    } else {
                        var survey_result = [];
                        var survey_answers = JSON.parse(result[0].survey_answers);
                        result1.forEach((ques) => {
                            survey_result.push({
                                question_id: ques.id,
                                question_description: ques.question_description,
                                choice_details: JSON.parse(ques.choice_details),
                                user_choice: survey_answers[ques.id].user_choice,
                                user_comment: survey_answers[ques.id].user_comment
                            });
                        });
                        return res.status(statusCodes.success).json({
                            response: responseMessages.success,
                            message: "Survey Result Fetched",
                            survey_result,
                        });
                    }
                });
            }
        }
    });
});

app.post("/edify/customer/upload-survey-report", checkCustomerAccess, (req, res) => {
    const {customer_id, report_input} = req.body;
    
    if(!report_input) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    const report_link = "http://localhost:5020/edify/customer/get-survey-report?cid="+customer_id;

    db.query("UPDATE customers SET survey_report_url = ? WHERE customer_id = ?", 
    [report_link, customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError, 
                error_message: err.message
            });
        } else {
            if(result.affectedRows > 0) {
                try {
                    const report_uint8array = new Uint8Array(report_input);
                    fs.writeFileSync(path.join(__dirname, "survey_reports", customer_id+".pdf"), report_uint8array);
                    return res.status(statusCodes.success).json({
                        response: responseMessages.success,
                        message: "Survey Report Uploaded",
                        report_link
                    });
                } catch (err) {
                    console.log(err);
                    return res.status(statusCodes.databaseError).json({
                        response: responseMessages.failure,
                        message: responseMessages.databaseError,
                        error_message: err.message
                    });
                }
            } else {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "Customer does not exist"
                });
            }
        }
    });
});

app.get("/edify/customer/get-survey-report", (req, res) => {
    const {cid} = req.query;

    if(!cid) {
        return res.status(statusCodes.insufficientData).send(
            "<h1>No Customer ID Provided</h1>"
        );
    }
    const report_path = path.join(__dirname, "survey_reports", cid+".pdf");
    if(fs.existsSync(report_path)) {
        return res.status(statusCodes.success).sendFile(report_path);
    } else {
        return res.status(statusCodes.noSuchResource).send(
            "<h1>Customer Report Not Found</h1>"
        );
    }
});

app.get("/edify/customer/download-survey-report", checkCustomerAccess, async (req, res) => {
    const {customer_id} = req.body;

    const report_path = path.join(__dirname, "survey_reports", customer_id+".pdf");
    if(fs.existsSync(report_path)) {
        return res.status(statusCodes.success).sendFile(report_path);
    } else {
        return res.status(statusCodes.noSuchResource).json({
            response: responseMessages.failure,
            message: "Customer Report does not exist"
        });
    }
});

app.get("/edify/customer/mail-report", checkCustomerAccess, async (req, res) => {
    const {customer_id, email} = req.body;

    const report_path = path.join(__dirname, "survey_reports", customer_id+".pdf");

    if(fs.existsSync(report_path)) {
        db.query("SELECT customer_name FROM customers WHERE customer_id = ?", [customer_id],
        async (err, result) => {
            if(err || result.length === 0) {
                console.log(err);
                return res.status(statusCodes.databaseError).json({
                    response: responseMessages.failure,
                    message: responseMessages.databaseError,
                    error_message: err? err.message : "No Such Customer"
                });
            } else {
                try {
                    await transporter.sendMail({
                        from: "Survey Team <" + process.env.SENDER_GMAIL + ">",
                        to: email,
                        subject: emailTemplates.customerReport.subject,
                        text: emailTemplates.customerReport.text.replace("{{name}}", result[0].customer_name),
                        attachments: [{
                            filename: "Survey_Report.pdf",
                            path: report_path
                        }]
                    });
                    return res.status(statusCodes.success).json({
                        response: responseMessages.success,
                        message: "Survey report sent to customer's email."
                    });
                }
                catch(err) {
                    console.log(err);
                    return res.status(statusCodes.errorInSendingEmail).json({
                        response: responseMessages.failure,
                        message: "Error in sending email."
                    });
                };
            }
        });
    } else {
        return res.status(statusCodes.noSuchResource).json({
            response: responseMessages.failure,
            message: "Customer Report does not exist"
        });
    }
});

// app.get("/edify/user/customer-ids", /*checkUserAccess,*/ (req, res) => {
//     db.query("SELECT customer_id FROM customers WHERE registration_status = 1 ORDER BY created_on DESC", 
//     (err, result) => {
//         if(err) {
//             console.log(err);
//             return res.status(statusCodes.databaseError).json({
//                 response: responseMessages.failure,
//                 message: responseMessages.databaseError,
//                 error_message: err.message
//             });
//         } else {
//             return res.status(statusCodes.success).json({
//                 response: responseMessages.success,
//                 message: "Customer IDs Fetched",
//                 customer_ids: result.map((customer) => customer.customer_id)
//             });
//         }
//     });
// });

app.get("/edify/user/customers-overview", (req, res) => {
    db.query("SELECT COUNT(*) AS total, SUM(survey_status = 'Not Started') AS not_started, SUM(survey_status = 'Pending') AS pending, SUM(survey_status = 'Complete') AS complete FROM customers WHERE registration_status = 1",
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "Customer Overview Fetched",
                overview: result[0]
            });
        }
    });
});

app.get("/edify/user/all-customer-details", (req, res) => {
    db.query("SELECT customer_id, customer_name, mobile_no, company_name, designation, company_email_id, created_on, survey_status FROM customers WHERE registration_status = 1 ORDER BY created_on DESC",
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            result.forEach((customer) => {
                customer.created_on = new Date(customer.created_on).toLocaleString();
            });
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "Customer Details Fetched",
                customer_details: result
            });
        }
    });
});

app.post("/edify/user/search-customers", (req, res) => {
    const {search_string} = req.body;

    if(!search_string) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: "Search String not provided"
        });
    }

    db.query("SELECT customer_id, customer_name, mobile_no, company_name, designation, company_email_id, created_on, survey_status FROM customers WHERE registration_status = 1 AND (customer_name LIKE ? OR company_email_id LIKE ? OR company_name LIKE ?) ORDER BY created_on DESC", 
    ["%"+search_string+"%", "%"+search_string+"%", "%"+search_string+"%"],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            result.forEach((customer) => {
                customer.created_on = new Date(customer.created_on).toLocaleString();
            });
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "Customer Details Fetched",
                customer_details: result
            });
        }
    });
});

app.get("/edify/user/notify-to-start", (req, res) => {
    db.query("SELECT company_email_id FROM customers WHERE DATEDIFF(CURRENT_TIMESTAMP(), created_on) > 2 AND registration_status = 1 AND survey_status = 'Not Started'",
    async (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else if(result.length === 0) {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "No customers to notify"
            });
        } else {
            var emails = [];
            result.forEach((customer) => {
                emails.push(customer.company_email_id);
            });
            try {
                await transporter.sendMail({
                    from: "Survey Team <" + process.env.SENDER_GMAIL + ">",
                    to: emails,
                    subject: emailTemplates.notifyToStart.subject,
                    text: emailTemplates.notifyToStart.text,
                    cc: "*******"
                });
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Notification emails sent to all pending customers"
                });
            } catch(err) {
                console.log(err);
                return res.status(statusCodes.errorInSendingEmail).json({
                    response: responseMessages.failure,
                    message: "Error in sending email."
                });
            }
        }
    });
});

app.get("/edify/user/notify-to-complete", (req, res) => {
    db.query("SELECT c.company_email_id FROM customers c JOIN survey_answers sa ON c.customer_id = sa.customer_id WHERE DATEDIFF(CURRENT_TIMESTAMP(), sa.latest_update_date) > 2 AND c.registration_status = 1 AND c.survey_status = 'Pending'",
    async (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else if(result.length === 0) {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "No customers to notify"
            });
        } else {
            var emails = [];
            result.forEach((customer) => {
                emails.push(customer.company_email_id);
            });
            try {
                await transporter.sendMail({
                    from: "Survey Team <" + process.env.SENDER_GMAIL + ">",
                    to: emails,
                    subject: emailTemplates.notifyToComplete.subject,
                    text: emailTemplates.notifyToComplete.text,
                    cc: "*******"
                });
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Notification emails sent to all pending customers"
                });
            } catch(err) {
                console.log(err);
                return res.status(statusCodes.errorInSendingEmail).json({
                    response: responseMessages.failure,
                    message: "Error in sending email."
                });
            }
        }
    });
});

app.get("/edify/user/get-customer-details", (req, res) => {
    const {customer_id} = req.query;

    if(!customer_id) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    db.query("SELECT customer_id, customer_name, company_name, company_url, designation, company_email_id, mobile_no, country, batch_id  FROM customers WHERE customer_id = ?", [customer_id],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "Customer Not Found"
                });
            } else {
                result[0].company_url = (result[0].company_url === null)? "" : result[0].company_url;
                result[0].designation = (result[0].designation === null)? "" : result[0].designation;
                result[0].mobile_no = (result[0].mobile_no === null)? "" : result[0].mobile_no;
                result[0].country = (result[0].country === null)? "" : result[0].country;
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "Customer Details Fetched", 
                    customer_details: result[0]
                });
            }
        }
    });
});

app.patch("/edify/user/edit-customer", (req, res) => {
    const {customer_name, company_name, mobile_no, customer_id, designation, country, company_url, batch_id} = req.body;
    if(!customer_name || !company_name || !mobile_no || !designation || !country || !company_url || !batch_id || !customer_id) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    db.query("UPDATE customers SET customer_name = ?, company_name = ?, mobile_no = ?, designation = ?, country = ?, company_url = ?, batch_id = ?, updated_on = CURRENT_TIMESTAMP() WHERE customer_id = ?",
    [customer_name, company_name, mobile_no, designation, country, company_url, batch_id, customer_id],
    (err) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "Details Updated"
            });
        }
    });
});

app.delete("/edify/user/delete-customer", (req, res) => {
    const {customer_id} = req.query;
    if(!customer_id) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    db.query("DELETE FROM customers WHERE customer_id = ?", [customer_id],
    (err) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "Customer Deleted"
            });
        }
    });
});

app.get("/edify/admin/get-all-users", (req, res) => {
    db.query("SELECT username, name, email, mob_no FROM users",
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "Users Fetched",
                users: result
            });
        }
    });
});

app.get("/edify/admin/get-user-details", (req, res) => {
    const {username} = req.query;

    if(!username) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    db.query("SELECT username, name, email, country_prefix, mob_no, company_name, company_domain FROM users WHERE username = ?", [username],
    (err, result) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            if(result.length === 0) {
                return res.status(statusCodes.noSuchResource).json({
                    response: responseMessages.failure,
                    message: "User Not Found"
                });
            } else {
                return res.status(statusCodes.success).json({
                    response: responseMessages.success,
                    message: "User Details Fetched",
                    user_details: result[0]
                });
            }
        }
    });
});

app.patch("/edify/admin/edit-user", (req, res) => {
    const {username, name, email, country_prefix, mob_no, company_name, company_domain} = req.body;

    if(!username || !name || !email || !country_prefix || !mob_no || !company_name || !company_domain) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    db.query("UPDATE users SET name = ?, email = ?, country_prefix = ?, mob_no = ?, company_name = ?, company_domain = ? WHERE username = ?",
    [name, email, country_prefix, mob_no, company_name, company_domain, username],
    (err) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "User Details Updated"
            });
        }
    });
});

app.delete("/edify/admin/delete-user", (req, res) => {
    const {username} = req.query;

    if(!username) {
        return res.status(statusCodes.insufficientData).json({
            response: responseMessages.failure,
            message: responseMessages.insufficientData
        });
    }

    db.query("DELETE FROM users WHERE username = ?", [username],
    (err) => {
        if(err) {
            console.log(err);
            return res.status(statusCodes.databaseError).json({
                response: responseMessages.failure,
                message: responseMessages.databaseError,
                error_message: err.message
            });
        } else {
            return res.status(statusCodes.success).json({
                response: responseMessages.success,
                message: "User Deleted"
            });
        }
    });
});

// Server Start
app.listen(port, () => console.log(`Server listening on http://localhost:${port}/`));

setInterval(() => {
    db.query("DELETE FROM users WHERE active_flag = 0 AND (CURRENT_TIMESTAMP() - created_on) > 2000",
    (err) => (err)? console.log(err.message) : "");
    db.query("DELETE FROM customer_otp WHERE (CURRENT_TIMESTAMP() - created_on) > 1500",
    (err) => (err)? console.log(err.message) : "");
}, 60000);