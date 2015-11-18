var common = require("./common");
var user = require("./user");

var api = { };

api.route = function(app) {
	app.post("/api/user/login", user.login);
	app.get("/logout", user.logout);
	app.post("/api/user/register", user.register);
	app.get("/api/verify_email/:code", user.verify_email);
};

// assuming user is logged in
api.user_info = function(email, callback) {
	common.db.collection("users").find({
		email: email
	}).toArray(function(err, users) {
		if (err) { return callback({ message: "Internal error (5)." }); }
		if (users.length != 1) {
			return callback({ message: "Internal error (6)." });
		} else {
			var user = users[0];
			return callback({
				uid: user["uid"],
				username: user["username"],
				firstname: user["firstname"],
				lastname: user["lastname"],
				email: user["email"],
				email_md5: common.hash("md5", email),
				provisional: user["provisional"],
			});
		}
	});
}

module.exports = api;