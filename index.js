const express = require('express');
const app = express();
const crypto = require('crypto');
const hashAlg = 'sha512';
const uuid = require('uuid/v4');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cookieLoginStr = 'brian-user-account-service-logged-in';
const cookieSiteLoginStr = 'brian-site-account-service-logged-in';

const firebase = require('firebase');
firebase.initializeApp({
	apiKey: "AIzaSyAiPbkUzzGtk7WU1yqkg36Td6LDwIdW5l4",
	authDomain: "brian-user-account-service.firebaseapp.com",
	databaseURL: "https://brian-user-account-service.firebaseio.com",
	projectId: "brian-user-account-service",
	storageBucket: "brian-user-account-service.appspot.com"
});
const database = firebase.database();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

function hash(str) {
	return crypto.createHash(hashAlg).update(str).digest('hex');
}

app.get('/api/cookie', (req, res) => {
	res.json(req.cookies);
});

app.get('/api/cookie/clear', (req, res) => {
	Object.keys(req.cookies).forEach(cookie => {
		res.clearCookie(cookie);
	})
	res.json({"Cookies removed": req.cookies});
});

app.get('/api/user/clear/all', (req, res) => {
	console.log("\nDelete all users requested.");
	database.ref('user').remove()
	.then(r => {
		res.json({"Success": "Deleted all users."})
		console.log("Removed all users.");
	})
	.catch(err => {
		res.json({"Error": err.toString()});
		console.log("Error: can't delete all users: ", err);
	});
});

app.get('/api/site/clear/all', (req, res) => {
	console.log("\nDelete all users requested.");
	database.ref('site').remove()
	.then(r => {
		res.json({"Success": "Deleted all Sites."})
		console.log("Removed all Sites.");
	})
	.catch(err => {
		res.json({"Error": err.toString()});
		console.log("Error: can't delete all sites: ", err);
	});
});

function createLoginCookie(res, user) {
	let id = uuid();

	return database.ref('user/' + user + '/id').push().set(id)
	.then(r => {
		res.cookie(cookieLoginStr, {
			'user': user,
			'id': id
		});	
		return true;
	}).catch(e => {
		console.log("Error: Cant set id for cookie in database: ", e);
		return false;
	});
}

// Returns a promise with the value of the data or null if invalid cookie
function validLoginCookie(cookie) {
	console.log("Validating cookie...");
	if(cookie === undefined) {
		console.log("No cookie to validate.");
		return Promise.reject("No cookie to validate.");
	}
	if(cookie.user === undefined || cookie.id === undefined) {
		console.log("Bad cookie.");
		return Promise.reject("Bad cookie.");
	}
	return database.ref('user/' + cookie.user).once('value')
		.then(snap => {
			if(snap.val() == null) {
				console.log("User doesn't exist.");
				return Promise.reject("User doesn't exist.");
			} else {
				if(snap.val().id === undefined) {
					return Promise.reject("Old cookie.");
				}

				let has = false;
				Object.keys(snap.val().id).forEach(key => {
					if(snap.val().id[key] === cookie.id) {
						has = true;
					}
				});
				if(!has) {
					console.log("Old cookie.");
					return Promise.reject("Old cookie.");
				}

				console.log("Valid cookie.");
				return snap.val();
			}
		});
}

// create a username
app.post('/api/create', (req, res) => {
	console.log("\nCreate account request.");
	console.log("data: ", req.body);

	if(req.body.user === undefined || req.body.pass === undefined) {
		res.json({"Error": "No username or password sent",
			"example": {
				"user": "Brian",
				"pass": "1234"
			}});
		console.log("Bad request.");
		return;
	}

	let user = req.body.user.toLowerCase();
	let pass = req.body.pass;

	database.ref('user/' + user).once('value')
	.then(snap => {
		// If we already have data for username.
		if(snap.val() !== null) {
			res.json({"Error": "Username is already in use."});
			console.log("Username already exists");
			return;
		}

		let salt = uuid();
		let id = uuid();

		Promise.all([database.ref('user/' + user).set({
			'salt': salt,
			'hash': hash(salt + pass),
			'id': {}
		}), createLoginCookie(res, user)])
		.then(arr => {
			if(arr[1] === false) {
				res.json({
					"Success": "Account created.",
					"Error": "Could not set cookie."
				});
				console.log("Success: Account created.\nError: Could not set cookie.");
				return;
			}

			res.json({"Success": "Account " + user + " created"});
			console.log("Success");
			return;
		})
		.catch(err => {
			res.json({"Error": "Can't create account."});
			console.log("Error: can't create account: ", err);
			return;
		});
	})
	.catch(err => {
		res.json({"Error": err.toString()})
		console.log("Error: ", err);
		return;
	});
});

app.post('/api/login', (req, res) => {
	console.log("\nLogin request.");
	console.log("data: ", req.body);
	console.log("cookies: ", req.cookies);

	// Check if already logged in
	validLoginCookie(req.cookies[cookieLoginStr])
	.then(val => {
		res.json({"Error": req.cookies[cookieLoginStr].user + " is already logged in."});
		console.log("Error: " + req.cookies[cookieLoginStr].user + " is already logged in.");
		return;
	})
	.catch(err => {
		if(req.body.user === undefined || req.body.pass === undefined) {
			res.json({"Error": "No username or password sent",
				"example": {
					"user": "Brian",
					"pass": "1234"
				}});
			console.log("Bad request.");
			return;
		}

		let user = req.body.user.toLowerCase();
		let pass = req.body.pass;

		database.ref('user/' + user).once('value')
		.then(snap => {
			// Does user exist
			if(snap.val() === null) {
				res.json({"Error": "Invalid username or password."});
				console.log("Error: Invalid username.");
				return;
			}

			// check password
			if(snap.val().hash !== hash(snap.val().salt + pass)) {
				res.json({"Error": "Invalid username or password."});
				console.log("Error: Invalid password.");
				return;
			}

			createLoginCookie(res, user)
			.then(r => {
				if(r === false) {
					res.json({"Error": "Could not create cookie."});
					console.log("Error: Could not create cookie.");
					return;
				}

				res.json({"Success": "Logged in"})
				console.log("Success: Logged in");
				return;
			});
		})
		.catch(err => {
			res.json({"Error": err.toString()});
			console.log("Error: ", err);
			return;
		});
	});
});

app.get('/api/read', (req, res) => {
	console.log("\nUser read request.");
	
	validLoginCookie(req.cookies[cookieLoginStr])
	.then(val => {
		res.json(val);
		console.log("Res: ", val);
	})
	.catch(err => {
		res.json({"Error": err.toString()});
		console.log("Error:", err);
	});
});

app.get('/api/login/clear', (req, res) => {
	console.log("\nClear logins request.");
	
	validLoginCookie(req.cookies[cookieLoginStr])
	.then(val => {
		database.ref('user/' + req.cookies[cookieLoginStr].user + '/id').remove()
		.catch(e => {
			res.json({"Error": e.toString()});
			console.log("Error: ", e);
			return;
		});
		res.json({"Success": "Cleared loggins"});	
		console.log("Success: Cleared loggins");
	})
	.catch(e => {
		res.json({"Error": e.toString()});
		console.log("Error:", e);
	});
});

function siteToDatabase(site) {
	let res = "";
	for(let char of site) {
		if(char === '.') {
			res += '-';
		} else {
			res += char;
		}
	}
	return res;
}

function createSiteLoginCookie(res, site) {
	let id = uuid();

	return database.ref('site/' + site + '/id').push().set(id)
	.then(r => {
		res.cookie(cookieSiteLoginStr, {
			'site': site,
			'id': id
		});	
		return true;
	}).catch(e => {
		console.log("Error: Cant set id for cookie in database: ", e);
		return false;
	});
}

function validSiteLoginCookie(cookie) {
	console.log("Validating Site cookie...");
	if(cookie === undefined) {
		console.log("No cookie to validate.");
		return Promise.reject("Cookie doesn't exist");
	}
	if(cookie.site === undefined || cookie.id === undefined) {
		console.log("Bad cookie.");
		return Promise.reject("Bad cookie.");
	}
	return database.ref('site/' + cookie.site).once('value')
		.then(snap => {
			if(snap.val() === null) {
				console.log("Site doesn't exist.");
				return Promise.reject("Site doesn't exist.");
			} else {
				if(snap.val().id === undefined) {
					return Promise.reject("Old cookie.");
				}

				console.log("Looking for: " + cookie.id);
				let has = false;
				Object.keys(snap.val().id).forEach(key => {
					console.log("Has: " + snap.val().id[key]);
					if(snap.val().id[key] === cookie.id) {
						has = true;
					}
				});
				if(!has) {
					console.log("Old cookie.");
					return Promise.reject("Old cookie.");
				}

				console.log("Valid cookie.");
				return snap.val();
			}
		});
}

app.post('/api/site/create', (req, res) => {
	console.log("\nCreate Site account request.");
	console.log("data: ", req.body);

	if(req.body.site === undefined || req.body.pass === undefined) {
		res.json({"Error": "No site or password sent",
			"example": {
				"site": "some.site.com",
				"pass": "1234"
			}});
		console.log("Bad request.");
		return;
	}

	let site = siteToDatabase(req.body.site.toLowerCase());
	let pass = req.body.pass;

	database.ref('site/' + site).once('value')
	.then(snap => {
		// If we already have data for username.
		if(snap.val() !== null) {
			res.json({"Error": "Site is already in use."});
			console.log("Site already exists.");
			return;
		}

		let salt = uuid();
		let id = uuid();

		Promise.all([database.ref('site/' + site).set({
			'salt': salt,
			'hash': hash(salt + pass),
			'id': {}
		}), createSiteLoginCookie(res, site)])
		.then(arr => {
			if(arr[1] === false) {
				res.json({
					"Success": "Site account created.",
					"Error": "Could not set cookie."
				});
				console.log("Success: Account created.\nError: Could not set cookie.");
				return;
			}

			res.json({"Success": "Site " + site + " created."});
			console.log("Success: Site " + site + " created.");
			return;
		})
		.catch(err => {
			res.json({"Error": "Can't create account."});
			console.log("Error: can't create account: ", err);
			return;
		});
	})
	.catch(err => {
		res.json({"Error": err.toString()})
		console.log("Error: ", err);
		return;
	});
});

app.post('/api/site/login', (req, res) => {
	console.log("\nSite Login request.");
	console.log("data: ", req.body);
	console.log("cookies: ", req.cookies);

	// Check if already logged in
	validSiteLoginCookie(req.cookies[cookieSiteLoginStr])
	.then(val => {
		res.json({"Error": req.cookies[cookieSiteLoginStr].site + " is already logged in."});
		console.log("Error: " + req.cookies[cookieSiteLoginStr].site + " is already logged in.");
		return;
	})
	.catch(err => {
		if(req.body.site === undefined || req.body.pass === undefined) {
			res.json({"Error": "No site or password sent",
				"example": {
					"site": "some.site.com",
					"pass": "1234"
				}});
			console.log("Bad request.");
			return;
		}

		let site = siteToDatabase(req.body.site.toLowerCase());
		let pass = req.body.pass;

		database.ref('site/' + site).once('value')
		.then(snap => {
			// Does site exist
			if(snap.val() === null) {
				res.json({"Error": "Invalid site or password."});
				console.log("Error: Invalid site.");
				return;
			}

			// check password
			if(snap.val().hash !== hash(snap.val().salt + pass)) {
				res.json({"Error": "Invalid site or password."});
				console.log("Error: Invalid password.");
				return;
			}

			createSiteLoginCookie(res, site)
			.then(r => {
				if(r === false) {
					res.json({"Error": "Could not create cookie."});
					console.log("Error: Could not create cookie.");
					return;
				}

				res.json({"Success": "Logged in."})
				console.log("Success: Logged in.");
				return;
			});
		})
		.catch(err => {
			res.json({"Error": err.toString()});
			console.log("Error: ", err);
			return;
		});
	});
});

app.get('/api/site/read', (req, res) => {
	console.log("\nSite read request.");
	
	validSiteLoginCookie(req.cookies[cookieSiteLoginStr])
	.then(val => {
		res.json(val);
		console.log("Res: ", val);
	})
	.catch(err => {
		res.json({"Error": err.toString()});
		console.log("Error:", err);
	});
});

app.get('/api/site/login/clear', (req, res) => {
	console.log("\nClear logins request.");
	
	validSiteLoginCookie(req.cookies[cookieSiteLoginStr])
	.then(val => {
		database.ref('site/' + req.cookies[cookieSiteLoginStr].site + '/id').remove()
		.catch(e => {
			res.json({"Error": e.toString()});
			console.log("Error: ", e);
			return;
		});
		res.json({"Success": "Cleared loggins"});	
		console.log("Success: Cleared loggins");
	})
	.catch(e => {
		res.json({"Error": e.toString()});
		console.log("Error:", e);
	});
});

app.get('/api/uuid', (req, res) => {
	res.json(uuid());
});

app.get('/', (req, res) => {
	res.sendFile(__dirname + "/public/main.html");

	let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
	let date = new Date();
	database.ref('ip/').once('value')
	.then(snap => snap.val())
	.then(val => { 
		let has = undefined;
		if(val != null) {
			Object.keys(val).forEach(key => {
				if(val[key].ip === ip) {
					has = key;
				}
			});
		}
		if(has === undefined) {
			console.log("New ip: " + ip);
			database.ref('ip/').push().set({
				'ip': ip,
				'first': date.toString(),
				'last': date.toString()
			});
		} else {
			database.ref('ip/' + has + '/last').set(date.toString());
		}
	})
	.catch(err => console.log("Error: " + err));
});

app.listen(process.env.PORT || 5000);