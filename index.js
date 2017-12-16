const express = require('express');
const app = express();
const crypto = require('crypto');
const hashAlg = 'sha512';
const uuid = require('uuid/v4');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cookieLoginStr = 'brian-user-account-service-logged-in';

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

app.get('/api/clear/all/user', (req, res) => {
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

// Returns a promise with the value of the data or null if invalid cookie
function validLoginCookie(cookie) {
	console.log("Validating cookie...");
	if(cookie === undefined) {
		console.log("No cookie to validate.");
		return Promise.resolve(null);
	}
	return database.ref('user/' + cookie.user).once('value')
		.then(snap => {
			if(snap == null) {
				console.log("User doesn't exist.");
				return null;
			} else {
				let has = false;
				Object.keys(snap.val().id).forEach(key => {
					if(snap.val().id[key] === cookie.id) {
						has = true;
					}
				});
				if(!has) {
					console.log("Old cookie.");
					return null;
				}

				console.log("Valid cookie.");
				return snap.val();
			}
		}).catch(e => {
			console.log("No id data.");
			return null;
		});
}

app.get('/api/read', (req, res) => {
	console.log("\nUser read request.");
	
	validLoginCookie(req.cookies[cookieLoginStr])
	.then(val => {
		if(val === null) {
			res.json({"Error": "Not logged in."});
			console.log("Error: User not logged in.");
			return;
		}

		res.json(val);
		console.log("Res: ", val);
	});
});

app.get('/api/clear/login', (req, res) => {
	console.log("\nClear logins request.");
	
	validLoginCookie(req.cookies[cookieLoginStr])
	.then(val => {
		if(val === null) {
			res.json({"Error": "Not logged in."});
			console.log("Error: User not logged in.");
			return;
		}

		database.ref('user/' + req.cookies[cookieLoginStr].user + '/id').remove()
		.catch(e => {
			res.json({"Error": e.toString()});
			console.log("Error: ", e);
			return;
		});
		res.json({"Sucess": true});	
	})
	.catch(e => {
		res.json({"Error": e.toString()});
		console.log("Error: ", e);
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

app.post('/api/login', (req, res) => {
	console.log("\nLogin request.");
	console.log("data: ", req.body);
	console.log("cookies: ", req.cookies);

	// Check if already logged in
	validLoginCookie(req.cookies[cookieLoginStr])
	.then(val => {
		if(val !== null) {
			res.json({"Error": req.cookies[cookieLoginStr].user + " is already logged in."});
			console.log("Error: " + req.cookies[cookieLoginStr].user + " is already logged in.");
			return;
		}

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
					return;
				}

				res.json({"Success": "Logged in"})
				console.log("Success");
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

app.post('/api/website/create', (req, res) => {
	
});

app.get('/api/uuid', (req, res) => {
	res.json(uuid());
});

app.get('/', (req, res) => {
	res.sendFile(__dirname + "/public/main.html");
});

app.listen(process.env.PORT || 5000);