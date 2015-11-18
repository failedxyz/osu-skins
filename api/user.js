var bcrypt = require("bcrypt");
var common = require("./common");
var moment = require("moment");
var request = require("request");
var validator = require("validator");

var get_user_ip = function(req) {
	return (req.headers["x-forwarded-for"] || "").split(",")[0] || req.connection.remoteAddress;
};

exports.login = function(req, res) {
	var email = req.body.email;
	var password = req.body.password;
	
	if (!(email && email.length > 0 && password && password.length > 0)) {
		return res.send({ success: 0, message: "Please fill out all the fields." });
	}
	
	login_user(req, email, password, function(result) {
		if (result.success == 1 && "sid" in result) {
			res.cookie("sid", result.sid, { signed: true });
			res.cookie("email", unescape(email), { signed: true });
		}
		res.send(result);
	});
};

exports.logout = function(req, res) {
	common.db.collection("tokens").update({
		type: "login",
		sid: req.signedCookies["sid"],
	}, {
		$set: {
			expired: true,
			expireTime: moment().format()
		}
	}, function() {
		res.clearCookie("sid", { signed: true });
		res.clearCookie("email", { signed: true });
		req.session.destroy();
		res.redirect("/");
	});
};

exports.register = function(req, res) {
	var username = req.body.username.replace(/\W+/g, "_");
	var email = req.body.email;
	var password = req.body.password;
	var recaptcha = req.body.recaptcha;
	
	if (!(username && username.length && email && email.length > 0 && password && password.length > 0)) {
		return res.send({ success: 0, message: "Please fill out all the fields." });
	}
	
	if (!validator.isEmail(email)) {
		return res.send({ success: 0, message: "That doesn't look like an email to me!" });
	}
	
	request.post(
		"https://www.google.com/recaptcha/api/siteverify",
		{ form: {
			secret: process.env.RECAPTCHA_SECRET,
			response: recaptcha,
			remoteip: get_user_ip(req)
		} },
		function (error, response, body) {
			if (true) { // !error && response.statusCode == 200 && JSON.parse(body)["success"] == true) {
				common.db.collection("users").find({
					email: email
				}).count(function(err, count) {
					if (err) { return res.send({ success: 0, message: "Internal error (1)." }); }
					if (count != 0) {
						return res.send ({ success: 0, message: "Someone's already registered this email." });
					} else {
						common.db.collection("users").find({
							username: { $regex : new RegExp("^" + username) }
						}).count(function(err3, existing) {
							if (existing != 0) {
								username += "." + existing;
							}
							var verify_code = common.token();
							var url = "http://" + common.DOMAIN + "/api/verify_email/" + verify_code;
							request.post({
									url: "https://api.sendgrid.com/api/mail.send.json",
									headers: {
										Authorization: "Bearer " + process.env.SENDGRID_APIKEY
									},
									form: {
										to: email,
										from: common.EMAIL,
										subject: "[ACTION REQUIRED] osu!skins - Please verify your email.",
										html: "<h1>Welcome to osu!skins!</h1> <p>We're super excited to have you on board our new platform. We're still in beta, so feel free to play around and give us feedback! Click the following link to verify your email.</p> <p><a href=\"" + url + "\">" + url + "</a></p> <p>Cheers,<br />IOException</p> <p>&nbsp;</p>"
									},
								}, function(error, response, body) {
									if (error) console.log("error = " + error);
									// if (response) console.log("response = " + response);
									// if (body) console.log("body = " + body);
									var uid = common.token();
									var salt = bcrypt.genSaltSync(10);
									var phash = bcrypt.hashSync(password, salt);
									var doc = {
										uid: uid,
										username: username,
										email: email,
										provisional: true,
										verify_code: verify_code,
										password: phash
									}
									common.db.collection("users").insert(doc, { w: 1 }, function(err2, doc) {
										if (err2) { return res.send({ success: 0, message: "Internal error (2)." }); }
										login_user(req, email, password, function(result) {
											if (result.success == 1 && "sid" in result) {
												res.cookie("sid", result.sid, { signed: true });
												res.cookie("email", unescape(email), { signed: true });
											}
											return res.send({ success: 1, message: "Registered!" });
										});
									});
								}
							);
						});
					}
				});
			} else {
				return res.send({ success: 0, message: "Please do the captcha." });
			}
		}
	);
};

exports.verify_email = function(req, res) {
	var code = req.params.code;
	if (!(code && code.length > 0)) {
		return res.send({ success: 0, message: "Code is missing or broken (1)." });
	}
	common.db.collection("users").update({
		verify_code: code
	}, {
		$set: { provisional: false },
		$unset: { verify_code: "" },
	}, function(err, result) {
		if (err) { return res.send({ success: 0, message: "Internal error (10)." }); }
		// console.log(result["result"]["nModified"]);
		if (result["result"]["nModified"] != 1) {
			return res.send({ success: 0, message: "Code is missing or broken (2)." });
		} else {
			res.redirect("/verify_email");
		}
	});
};

var login_user = function(req, email, password, callback) {
	common.db.collection("users").find({
		email: email
	}).toArray(function(err, users) {
		if (err) { return callback({ success: 0, message: "Internal error (3)." }); }
		if (users.length != 1) {
			return callback({ success: 0, message: "Please check if your email and password are correct." });
		} else {
			var user = users[0];
			var correct = bcrypt.compareSync(password, user["password"]);
			if (correct) {
				var sid = common.token();
				var session_information = {
					type: "login",
					uid: user["uid"],
					sid: sid,
					created: moment().format(),
					expired: false,
					ua: req.headers["user-agent"],
					ip: get_user_ip(req)
				};
				common.db.collection("tokens").insert(session_information, { w: 1 }, function(err2, doc) {
					if (err2) { return callback({ success: 0, message: "Internal error (4)." }); }
					return callback({ success: 1, message: "Successfully logged in.", sid: sid });
				});
			} else {
				return callback({ success: 0, message: "Please check if your email and password are correct." });
			}
		}
	});
};