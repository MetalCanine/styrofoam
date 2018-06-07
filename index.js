/* eslint no-var: 0 */
/* eslint prefer-destructuring: 0 */
/* eslint no-control-regex: 0 */
/* eslint no-buffer-constructor: 0 */

var fs = require('fs');

/**
	* reads a line from the console through the system's TTY file descriptor
	*
	* @returns {string} string from the console
*/
function read() {
	// Thank you to the readline-sync package and anseki for guidance
	var encoding = 'utf8';
	var fileDescriptor = null;
	var buffer;
	var bufferSize = 1024;
	var readSize;
	var input = '';
	var chunk;
	var atEOL;

	// Attempt to set up read for platform's stdin file descriptor
	// If we're currently running on Windows
	if (process.platform === 'win32') {
		process.stdin.pause();
		fileDescriptor = process.stdin.fd;
	}
	// If we're currently running on a Unix like
	else {
		process.stdin.pause();
		fileDescriptor = fs.openSync('/dev/tty', 'r');
	}

	buffer = Buffer.alloc(bufferSize);

	do {
		readSize = fs.readSync(fileDescriptor, buffer, 0, bufferSize);

		if (readSize > 0) {
			chunk = buffer.toString(encoding, 0, readSize);
		}
		else {
			chunk = '';
		}

		if (chunk.match(/^(.*)[\r\n]/)) {
			chunk = (chunk.match(/^(.*)[\r\n]/) || [])[1];
			atEOL = true;
		}

		if (chunk) {
			chunk = chunk.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
			input += chunk;
		}
	} while (!atEOL && input.length <= bufferSize);

	return input;
}

/**
	* writes a line of data to the console through stdout
	*
	* @params {any} text
*/
function write(text) {
	process.stdout.write(text);
}

module.exports = {
	read,
	write,
};
