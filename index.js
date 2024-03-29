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

function saveIp(ip, purpose, date, data, prefix = "") {
	return Promise.all([
		database.ref(prefix + 'ip/' + ip + '/request/' + purpose + '/' + date.getTime()).set(true),
		database.ref(prefix + 'ip/' + ip + '/purpose/' + purpose).once('value')
		.then(snap => snap.val())
		.then(json => {
			if(json === null) {
				json = {amount: 1};
			} else {
				json.amount++;
			}
			database.ref(prefix + 'ip/' + ip + '/purpose/' + purpose).set(json);
		}),
		database.ref(prefix + 'ip/request/' + date.getTime()).set(data)
	]);
}

function saveIpMiddleware(req, res, next) {
	let ip = toDatabaseString(req.headers['x-forwarded-for'] || req.connection.remoteAddress);
	let purpose = toDatabaseString(req.path);
	let date = new Date();
	let data = {purpose: purpose, date: date.toString(), body: {}, cookies: {},};
	for(var key in req.body) {
		if(key.toLowerCase().indexOf('pass') !== -1) {
			data.body[key] = '[password]';
		} else {
			data.body[key] = req.body[key];
		}
	}
	for(var key in req.cookies) {
		data.cookies[key] = req.cookies[key];
	}

	saveIp(ip, purpose, date, data);
	// database.ref('ip/' + ip + '/request/' + purpose + '/' + date.getTime()).set(true);
	// database.ref('ip/' + ip + '/purpose').once('value')
	// .then(snap => snap.val())
	// .then(json => {
	// 	if(json === null) {
	// 		json = {};
	// 	}
	// 	if(json[purpose] === undefined) {
	// 		json[purpose] = {amount: 1};
	// 	} else {
	// 		json[purpose].amount++;
	// 	}
	// 	database.ref('ip/' + ip + '/purpose').set(json).catch(err => console.log("Error 1:", err));
	// }).catch(err => console.log("Error 2:", err));
	// database.ref('ip/request/' + date.getTime()).set(data);
	next();
}

app.use(saveIpMiddleware);

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
	.then(() => createLoginCookie(res, loginCookieStr, user))
	.then(r => {
		console.log("Success: User " + user + " created and logged in.");
		return res.json({ status: 'success', message: 'User created and logged in.'});
	})
	.catch(err => res.json(err));
});

app.post('/api/login', (req, res) => {
	console.log("\nLogin request.");
	console.log("data: ", req.body);

	if(req.body.user === undefined || req.body.pass === undefined) {
		console.log("Bad request.");
		res.json({status: 'error', message: 'Bad request.', example: {user: 'Brian', pass: 'pass'}});
		return;
	}

	let user = req.body.user.toLowerCase();
	let pass = req.body.pass;

	new Promise((resolve, reject) => {
		if(req.cookies[loginCookieStr] !== undefined && req.cookies[loginCookieStr].user === user) {
			validateCookie(req.cookies[loginCookieStr])
			.then(val => {
				resolve();
			})
			.catch(err => {
				reject();
			});
		} else {
			reject();
		}
	}).then(val => {
		console.log("Success: already logged in.");
		res.json({ status: 'success', message: 'You are already logged in.'});
	})
	.catch(err => {
		if(!validDatabaseString(user)) {
			console.log("Invalid username: " + user);
			res.json({status: 'error', message: 'Username can not contain /.$#[]'});
			return;
		}

		return database.ref('user/' + user).once('value')
			.then(snap => snap.val())
			.catch(err => {
				console.log("Error accessing database: ", err)
				return Promise.reject({ tatus: 'error', message: 'Error accessing database: ' + err.toString()})
			})
			.then(val => {
				if(val === null) {
					console.log("Invalid username.");
					return Promise.reject({status: 'error', message: 'Invalid username or password.'})
				}
				if(val.hash !== hash(val.salt + pass)) {
					console.log("Invalid password");
					return Promise.reject({status: 'error', message: 'Invalid username or password.'})
				}

				return createLoginCookie(res, loginCookieStr, user);
			})
			.then(r => {
				console.log("Success: logged in.");
				res.json({status: 'success', message: 'Logged in.'});
			})
	})
	.catch(err => res.json(err));
});

app.post('/api/login/change', (req, res) => {
	console.log("\nChange password request.");
	console.log("data: ", req.body);

	let user = req.body.user.toLowerCase();
	let pass = req.body.pass;
	let newPass = req.body.newPass;

	if(req.body.user === undefined || req.body.pass === undefined || req.body.newPass === undefined) {
		console.log("Bad reqest.");
		res.json({status: 'error', message: 'Bad request.', example: {user: 'Brian', pass: 'pass', newPass: 'newPass'}});
		return;
	}
	if(!validDatabaseString(user)) {
		console.log("Invalid username: " + user);
		res.json({status: 'error', message: 'Username can not contain /.$[]'});
		return;
	}

	database.ref('user/' + user).once('value')
		.then(snap => snap.val())
		.catch(err => {
			console.log("Error accessing database: ", err);
			return Promise.reject({status: 'error', message: 'Error accesing database: ' + err.toString()});
		})
		.then(val => {
			if(val === null) {
				console.log("Invalid username.");
				return Promise.reject({status: 'error', message: 'Invalid username or password.'});
			}
			if(val.hash !== hash(val.salt + pass)) {
				console.log("Invalid password.");
				return Promise.reject({status: 'error', message: 'Invalid username or password.'});
			}

			console.log("Updating user.");
			let salt = uuid();
			return database.ref('user/' + user).set({salt: salt, hash: hash(salt + newPass)})
				.catch(err => {
					console.log("Error accessing database: ", err);
					return Promise.reject({ status: 'error', message: "Error accessing database: " + err.toString() })
				})
		}).then(() => createLoginCookie(res, loginCookieStr, user))
		.then(r => {
			console.log("Success: password changed.");
			return res.json({status: 'success', message: 'Password changed.'})
		})
		.catch(err => res.json(err));
});

app.get('/api/login/clear', (req, res) => {
	console.log("\nClear logins request.");
	validateCookie(req.cookies[loginCookieStr])
	.catch(err => Promise.reject({ status: 'error', message: 'Not logged in.'}))
	.then(val => database.ref('user/' + req.cookies[loginCookieStr].user + '/id').remove()
		.then(() => {
			console.log("Success: Logins cleared.");
			return {status: 'success', message: 'Logins cleared'}
		})
		.catch(err => {
			console.log("Error: ", err);
			return Promise.reject({ status: 'error', message: 'Error accessing database: ' + err.toString()})
		})
	)
	.then(() => createLoginCookie(res, loginCookieStr, req.cookies[loginCookieStr].user))
	.then(() => res.json({ status: 'success', message: 'Logins cleared'}))
	.catch(err => res.json(err));
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

	if(req.body.ip === undefined || req.body.purpose === undefined || req.body.data === undefined) {
		console.log("Bad request.");
		res.json({status: 'error', message: 'Bad request.', example: { ip: 'their ip', purpose: 'home', data: {the: 'data', you: 'want', to: 'store'}}});
		return;
	}

	validateCookie(req.cookies[loginCookieStr])
	.catch(err => Promise.reject({status: 'error', message: 'Not logged in.'}))
	.then(() => saveIp(toDatabaseString(req.body.ip), toDatabaseString(req.body.purpose), new Date(), req.body.data, req.cookies[loginCookieStr].user + '/'))
		.catch(err => {
			console.log("Error accessing database.");
			return Promise.reject({status: 'error', message: 'Error accessing database.'})
		})
	.then(val => {
		console.log("Success: Ip saved.");
		res.json({status: 'success', message: 'Ip saved.'});
	})
	.catch(err => res.json(err))
});

app.get('/api/uuid', (req, res) => {
	res.json(uuid());
});

app.get('/', (req, res) => {
	res.sendFile(__dirname + "/public/main.html");
});

app.get('/test', (req, res) => {
	res.sendFile(__dirname + "/public/test.html");
})

app.listen(process.env.PORT || 5000);