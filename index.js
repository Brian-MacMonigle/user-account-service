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


function siteToDatabase(site) {
	let res = "";
	for(let char of site) {
		if(char === '.' || char === '/') {
			res += '-';
		} else {
			res += char;
		}
	}
	return res;
}

function saveIp(req, res, next) {
	let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
	let date = new Date().toString();
	let purpose = siteToDatabase(req.url);
	database.ref('ip/').once('value')
	.then(snap => snap.val())
	.then(val => { 
		let key = undefined;
		if(val != null) {
			Object.keys(val).forEach(k => {
				if(val[k].ip === ip) {
					key = k;
				}
			});
		}
		if(val === null || key === undefined) {
			let json = {
				'ip': ip
			}
			json[purpose] = {
				'first': date,
				'last': date,
				'amount': 1
			}
			database.ref('ip/').push().set(json);
		} else {
			let json = val[key] || {'ip': ip};

			if(json[purpose] === undefined) {
				json[purpose] = {
					'first': date,
					'last': date,
					'amount': 1
				}
			} else {
				json[purpose] = {
					'first': json[purpose].first || date,
					'last': date,
					'amount': ++json[purpose].amount || 1
				}
			}
			database.ref('ip/' + key).set(json);
		}
	})
	.catch(err => {
		console.log("Error: " + err);
	});
	next();
}

app.use(saveIp);

function hash(str) {
	return crypto.createHash(hashAlg).update(str).digest('hex');
}


app.get('/api/cookie', (req, res) => {
	res.json(req.cookies);

	database.ref('test/').push().set({
		'cookies': req.cookies,
		'id': '/api/cookie'
	})
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

function createSiteLoginCookie(res, site) {
	let id = uuid();

	return database.ref('site/' + site + '/id').push().set(id)
	.then(r => {
		res.cookie(cookieSiteLoginStr, {
			'site': site,
			'id': id
		}, {httpOnly: false})
		.header('Access-Control-Allow-Origin', '*')
		.header('Access-Control-Allow-Credentials', 'true');	
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

	database.ref('test/').push().set({
		'data': req.body,
		'cookie': req.cookies || "null"
	});

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

app.post('/api/site/read', (req, res) => {
	console.log("\nSite read request.");
	console.log("Body: ", req.body);

	if(req.body.name === undefined) {
		res.json({"Error": "No name or value sent",
				"example": {
					"name": "nameOfAttribute",
				}});
			console.log("Bad request.");
	}

	let name = req.body.name;

	validSiteLoginCookie(req.cookies[cookieSiteLoginStr])
	.then(val => {
		database.ref(req.cookies[cookieSiteLoginStr].site + '/' + name).once('value')
		.then(snap => {
			res.json(snap.val());
			console.log("Send data: ", snap.val());
		})
		.catch(err => {
			res.json({"Error": err});
			console.log("Error: ", err);
		})
	})
	.catch(err => {
		res.json({"Error": err.toString()});
		console.log("Error: ", err);
	})
});

app.post('/api/site/write', (req, res) => {
	console.log("\nSite store request.");
	console.log("Body: ", req.body);

	if(req.body.name === undefined || req.body.value === undefined) {
		res.json({"Error": "No name or value sent",
				"example": {
					"name": "name",
					"value": "value"
				},
				"example2": {
					"name": "name",
					"value": {
						"some": "json"
					}
				}});
			console.log("Bad request.");
	}

	let name = req.body.name;
	let value;
	try {
		value = JSON.parse(req.body.value);
	} catch (e) {
		value = req.body.value;
	}

	validSiteLoginCookie(req.cookies[cookieSiteLoginStr])
	.then(val => {
		database.ref(req.cookies[cookieSiteLoginStr].site + '/' + name).set(value)

		try {
			res.json({"Success": JSON.stringify(value) + " written to " + name + "."});
		} catch (e) {
			res.json({"Success": value.toString() + " written to " + name + "."})
		}
	})
	.catch(err => {
		res.json({"Error": err.toString()});
		console.log("Error: ", err);
	})
})

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
});

app.listen(process.env.PORT || 5000);