/* eslint no-var: 0 */
/* eslint prefer-destructuring: 0 */
/* eslint no-control-regex: 0 */
/* eslint no-buffer-constructor: 0 */

var fs = require('fs');

function read() {
	var encoding = 'utf8';
	var bufferSize = 1024;
	var fileDescriptor = null;
	var input = '';
	var atEol;
	var buffer;
	var readSize;
	var chunk;
	var line;

	// Attempt to set up read for platform's stdin file descriptor
	// If we're currently running on windows
	if (process.platform === 'win32') {
		process.stdin.pause();
		fileDescriptor = process.stdin.fd;
	}
	// If we're currently running on a Unix like
	else {
		process.stdin.pause();
		fileDescriptor = fs.openSync('/dev/tty', 'r');
	}

	// Check `allocUnsafe` to make sure of the new API.
	buffer = Buffer.allocUnsafe && Buffer.alloc ? Buffer.alloc(bufferSize) : new Buffer(bufferSize);

	while (true) {
		readSize = fs.readSync(fileDescriptor, buffer, 0, bufferSize);

		if (readSize > 0) {
			chunk = buffer.toString(encoding, 0, readSize);
		}
		else {
			chunk = '';
		}

		line = (chunk.match(/^(.*)[\r\n]/) || [])[1];

		if (chunk && typeof (line) === 'string') {
			chunk = line;
			atEol = true;
		}

		// other ctrl-chars
		if (chunk) {
			chunk = chunk.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
			input += chunk;
		}

		if (readSize === 0 || atEol || input.length >= bufferSize) {
			break;
		}
	}

	return input;
}

function write(text) {
	process.stdout.write(text);
}

module.exports = {
	read,
	write,
};
