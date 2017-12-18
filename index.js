var readline = require('readline-sync');

function read() {
	return readline.question();
}

function write(text) {
	process.stdout.write(text);
}

module.exports = {
	read,
	write,
};
