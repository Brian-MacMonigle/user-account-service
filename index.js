const express = require('express');
const app = express();
const crypto = require('crypto');
const hashAlg = 'sha512';
const uuid = require('uuid/v4');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const loginCookieStr = 'brian-user-account-service-logged-in';
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

function validDatabaseString(str) {
	for(let char of str) {
		if(char === '/' || char === '.' || char === '$' || char === '#' || char === '[' || char === ']') {
			return false;
		}
	}
	return true;
}

function validDatabasePath(str) {
	for(let char of str) {
		if(char === '.' || char === '$' || char === '#' || char === '[' || char === ']') {
			return false;
		}
	}
	return true;
}

function toDatabaseString(str) {
	let res = "";
	for(let char of str) {
		switch(char) {
			case '/':
				res += '-';
				break;
			case '.':
				res += ',';
				break;
			default:
				res += char;
		}
	}
	return res;
}

function saveIp(req, res, next) {
	let ip = toDatabaseString(req.headers['x-forwarded-for'] || req.connection.remoteAddress);
	let date = new Date().getTime();
	let purpose = toDatabaseString(req.path);

	database.ref('ip/' + ip).once('value')
	.then(snap => snap.val())
	.then(val => {
		if(val === null) {
			val = {[purpose]: {first: date, last: date, amount: 1}};
		} else if(val[purpose] === undefined) {
			val[purpose] = {first: date, last: date, amount: 1};
		} else {
			val[purpose].last = date;
			val[purpose].amount++;
		}
		return database.ref('ip/' + ip).set(val)
			.catch(err => Promise.reject(err.toString()));
	})
	.catch(err => console.log("Error saving ip: ", err))
	next();
}

app.use(saveIp);

function hash(str) {
	return crypto.createHash(hashAlg).update(str).digest('hex');
}

function addLoginCookie(res, cookie, user, id) {
	console.log("Adding cookie...");
	return database.ref('user/' + user + '/id').push().set(id)
	.then(r => {
		res.cookie(cookie, { user: user, id: id	});
		console.log("Cookie set.");
		return {status: 'success', data: { 'cookie': { user: user, id: id} }};
	})
	.catch(e => {
		console.log("Error: Cant set id for cookie in database: ", e);
		return Promise.reject({status: 'error', message: e.toString()});
	})
}

function createLoginCookie(res, cookie, user) {
	return addLoginCookie(res, cookie, user, uuid());
}

function validateCookie(cookie) {
	console.log("Validating cookie...");
	if(cookie === undefined) {
		console.log("No cookie to validate.");
		return Promise.reject({status: 'error', message: 'No cookie to validate.'});
	}
	if(cookie.user === undefined) {
		console.log("Bad cookie.");
		return Promise.reject({status: 'error', message: 'A user is required in cookie.user.'});
	}
	if(cookie.id === undefined) {
		console.log("Bad cookie.");
		return Promise.reject({status: 'error', message: 'A id is required in cookie.id'})
	}
	return database.ref('user/' + cookie.user + '/id').once('value')
		.then(snap => snap.val())
		.catch(err => {
			console.log("Error: ", err);
			return Promise.reject({status: 'error', message: err});
		})
		.then(ids => {
			if(ids === null) {
				console.log("Error: Invalid cookie: Id not in database.");
				return Promise.reject({status: 'error', message: 'Invalid cookie.'});
			}

			for(let key in ids) {
				if(ids[key] === cookie.id) {
					console.log("Success: valid cookie.");
					return {status: 'success', data: null};
				}
			}
			console.log("Error: Invalid cookie: Id not in database.");
			return Promise.reject({status: 'error', message: 'Invalid cookie.'});
		});
}

app.get('/api/cookie', (req, res) => {
	res.json(req.cookies);
});

app.get('/api/cookie/clear', (req, res) => {
	for(var key in req.cookies) {
		res.clearCookie(key);
	}
	res.json({status: 'success', data: {'cookies-removed': req.cookies}});
});

// create a username
app.post('/api/create', (req, res) => {
	console.log("\nCreate account request.");
	console.log("data: ", req.body);

	let user = req.body.user.toLowerCase();
	let pass = req.body.pass;

	if(req.body.user === undefined || req.body.pass === undefined) {
		console.log("Bad request.");
		res.json({status: 'error', message: 'Bad request', example: {user: 'Brian', pass: 'pass'}});
		return;
	}
	if(!validDatabaseString(user)) {
		console.log("Invalid username: " + user);
		res.json({status: 'error', message: 'Username can not contain /.$#[]'});
		return;
	}


	database.ref('user/' + user).once('value')
	.then(snap => snap.val())
	.then(val => {
		// User already exists
		if(val !== null) {
			console.log("Error: Username " + user + " already exists.");
			return Promise.reject({status: 'error', message: 'Username already exists.'});
		}

		let salt = uuid();
		return database.ref('user/' + user).set({ salt: salt, hash: hash(salt + pass) })
			.catch(err => {
				console.log("Error accessing database: ", err);
				return Promise.reject({ status: 'error', message: "Error accessing database: " + err.toString() })
			});
	})
	.then(r => createLoginCookie(res, loginCookieStr, user))
	.then(r => {
		console.log("Success: User " + user + " created and logged in.");
		return res.json({ status: 'success', message: 'User created and logged in.'});
	})
	.catch(err => res.json(err));
});

app.post('/api/login', (req, res) => {
	console.log("\nLogin request.");
	console.log("data: ", req.body);

	let user = req.body.user.toLowerCase();
	let pass = req.body.pass;

	// Check if already logged in
	validateCookie(req.cookies[loginCookieStr])
	.then(val => {
		console.log("Success: already logged in.");
		res.json({ status: 'success', message: 'You are already logged in.'});
	})
	.catch(err => {
		if(req.body.user === undefined || req.body.pass === undefined) {
			console.log("Bad request.");
			res.json({status: 'error', message: 'Bad request', example: {user: 'Brian', pass: 'pass'}});
			return;
		}
		if(!validDatabaseString(user)) {
			console.log("Invalid username: " + user);
			res.json({status: 'error', message: 'Username can not contain /.$#[]'});
			return;
		}

		return database.ref('user/' + user).once('value')
			.then(snap => snap.val())
			.catch(err => {
				console.log("Error accessing database: ", err)
				return Promise.reject({ status: 'error', message: 'Error accessing database: ' + err.toString() })
			})
			.then(val => {
				if(val === null) {
					console.log("Invalid username.");
					return Promise.reject({ status: 'error', message: 'Invalid username or password.'})
				}
				if(val.hash !== hash(val.salt + pass)) {
					console.log("Invalid password");
					return Promise.reject({ status: 'error', message: 'Invalid username or password.'})
				}

				return createLoginCookie(res, loginCookieStr, user);
			})
			.then(r => {
				console.log("Success: logged in.");
				res.json({ status: 'success', message: 'Logged in.'});
			})
	})
	.catch(err => res.json(err.toString()));
});

function clearLogins(cookie) {
	console.log("Clearing loggins...");
	return validateCookie(cookie)
		.catch(err => Promise.reject({ status: 'error', message: 'Not logged in.'}))
		.then(val => database.ref('user/' + cookie.user + '/id').remove()
			.then(() => {
				console.log("Success: Logins cleared.");
				return {status: 'success', message: 'Logins cleared'}
			})
			.catch(err => {
				console.log("Error: ", err);
				Promise.reject({ status: 'error', message: 'Error accessing database: ' + err.toString()})
			})
		);
}

app.get('/api/login/clear', (req, res) => {
	// only new line because function already creates text we want
	console.log("\n");
	clearLogins(req.cookies[loginCookieStr])
	.then(r => {
		return createLoginCookie(res, loginCookieStr, req.cookies[loginCookieStr].user);
	})
	.then(r => {
		res.json({ status: 'success', message: 'Logins cleared'});	
	})
	.catch(err => {
		res.json(err)
	});
});

app.get('/api/read', (req, res) => {	
	console.log("\nUser read request.");
	console.log("data: { path: '" + req.query.path + "' }");

	if(req.query.path === undefined) {
		console.log("Bad request");
		res.json({ status: 'error', message: 'Invalid query', example: '/api/read?path=data/insideData'})
		return;
	}

	if(!validDatabasePath(req.query.path)) {
		console.log("Bad request");
		res.json({ status: 'error', message: 'Name may not contain .$#[]'});
	}

	validateCookie(req.cookies[loginCookieStr])
	.catch(err => Promise.reject({ status: 'error', message: 'Not logged in.'}))
	.then(val => {
		return database.ref(req.cookies[loginCookieStr].user + '/' + req.query.path).once('value')
		.then(snap => snap.val())
		.then(val => {
			console.log("Success: sent:", val);
			res.json({ status: 'success', message: val, path: req.query.path});
		})
		.catch(err => {
			console.log("Error accessing database: ", err);
			return Promise.reject({ status: 'error', message: err.toString()});
		})
	})
	.catch(err => res.json(err));
});

app.post('/api/write', (req, res) => {
	console.log("\nUser write request.");
	console.log("data: ", req.body);

	if(req.body.path === undefined || req.body.data === undefined) {
		console.log("Bad request.");
		res.json({ status: 'error', message: 'Bad request.', example: { path: 'dataName', data: 'coolData'}});
		return;
	}

	if(!validDatabasePath(req.body.path)) {
		console.log("Bad request");
		res.json({ status: 'error', message: 'Name may not contain .$#[]'});
		return;
	}

	validateCookie(req.cookies[loginCookieStr])
	.catch(err => Promise.reject({ status: 'error', message: 'Not logged in.'}))
	.then(val => {
		return database.ref(req.cookies[loginCookieStr].user + '/' + req.body.path).set(req.body.data)
		.then(() => {
			console.log("Success: " + req.body.path + " = " + req.body.data + ".");
			res.json({ status: 'success', message: req.body.path + " = " + req.body.data + "."});
		})
		.catch(err => {
			console.log("Error accessing database: ", err);
			return Promise.reject({ status: 'error', message: err.toString()});
		})
	})
	.catch(err => res.json(err));
})

app.post('/api/write/ip', (req, res) => {
	console.log("\nUser write ip request.");
	console.log("data: ", req.body);

	if(req.body.ip === undefined || req.body.path === undefined) {
		console.log("Bad request.");
		res.json({ status: 'error', message: 'Bad request.', example: { ip: 'their ip', path: 'their path'}});
		return;
	}

	let date = new Date().getTime();

	let path = req.cookies[loginCookieStr].user + '/ip/' + toDatabaseString(req.body.ip);

	validateCookie(req.cookies[loginCookieStr])
	.catch(err => Promise.reject({ status: 'error', message: 'Not logged in.'}))
	.then(() => database.ref(path).once('value')
			.then(snap => snap.val()))
	.then(val => {
		if(val === null) {
			val = {[req.body.path]: {first: date, last: date, amount: 1}};
		} else if(val[req.body.path] === undefined) {
				val[req.body.path] = {first: date, last: date, amount: 1};
		} else {
				val[req.body.path].last = date;
				val[req.body.path].amount++;
		}
		return database.ref(path).set(val)
		.catch(err => Promise.reject({ status: 'error', message: err.toString()}));
	})
	.then(() => {
		console.log("Success: ip saved.");
		res.json({ status: 'success', message: 'Ip saved.'})
	})
	.catch(err => res.json(err));
})

app.get('/api/uuid', (req, res) => {
	res.json(uuid());
});

app.get('/', (req, res) => {
	res.sendFile(__dirname + "/public/main.html");
});

app.listen(process.env.PORT || 5000);