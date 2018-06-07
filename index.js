/* eslint no-var: 0 */
/* eslint prefer-destructuring: 0 */
/* eslint prefer-arrow-callback: 0 */
/* eslint prefer-template: 0 */
/* eslint no-underscore-dangle: 0 */
/* eslint no-path-concat: 0 */
/* eslint func-names: 0 */

var fs = require('fs');
var childProc = require('child_process');
var pathUtil = require('path');
var crypto = require('crypto');
var tempdir = require('os').tmpdir();

var ALGORITHM_CIPHER = 'aes-256-cbc';
var ALGORITHM_HASH = 'sha256';
var DEFAULT_ERR_MSG = 'The current environment doesn\'t support interactive reading from TTY.';
var TTY = process.binding('tty_wrap').TTY;
var defaultOptions = {
	prompt: '> ',
	hideEchoBack: false,
	mask: '*',
	limit: [],
	limitMessage: 'Input another, please.$<( [)limit(])>',
	defaultInput: '',
	trueValue: [],
	falseValue: [],
	caseSensitive: false,
	keepWhitespace: false,
	encoding: 'utf8',
	bufferSize: 1024,
	print: undefined,
	history: true,
	cd: false,
	phContent: undefined,
	preCheck: undefined,
};
var fdR = 'none';
var fdW;
var ttyR;
var isRawMode = false;
var extHostPath;
var extHostArgs;
var salt = 0;

function encodeArg(arg) {
	return arg.replace(/[^\w\u0080-\uFFFF]/g, function (chr) {
		return '#' + chr.charCodeAt(0) + ';';
	});
}

function getHostArgs(options) {
	var conf = {
		display: 'string',
		displayOnly: 'boolean',
		keyIn: 'boolean',
		hideEchoBack: 'boolean',
		mask: 'string',
		limit: 'string',
		caseSensitive: 'boolean',
	};
	var args = [];

	Object.keys(conf).forEach(function (optionName) {
		if (conf[optionName] === 'boolean') {
			if (options[optionName]) {
				args.push('--' + optionName);
			}
		}
		else if (conf[optionName] === 'string') {
			if (options[optionName]) {
				args.push('--' + optionName, encodeArg(options[optionName]));
			}
		}
	});

	return extHostArgs.concat(args);
}

function getTempfile(name) {
	var filepath;
	var suffix = '';
	var fd;

	while (true) {
		filepath = pathUtil.join(tempdir, name + suffix);

		try {
			fd = fs.openSync(filepath, 'wx');
		}
		catch (e) {
			if (e.code !== 'EEXIST') {
				throw e;
			}
			else {
				suffix += 1;
			}
		}

		fs.closeSync(fd);
		break;
	}

	return filepath;
}

// piping via files (for Node.js v0.10-)
function _execFileSync(options, execOptions) {
	var hostArgs;
	var shellPath;
	var shellArgs;
	var res = {};
	var exitCode;
	var extMessage;
	var pathStdout = getTempfile('readline-sync.stdout');
	var pathStderr = getTempfile('readline-sync.stderr');
	var pathExit = getTempfile('readline-sync.exit');
	var pathDone = getTempfile('readline-sync.done');
	var shasum;
	var decipher;
	var password;

	shasum = crypto.createHash(ALGORITHM_HASH);
	shasum.update('' + process.pid + (salt += 1) + Math.random());
	password = shasum.digest('hex');
	decipher = crypto.createDecipher(ALGORITHM_CIPHER, password);

	hostArgs = getHostArgs(options);
	if (process.platform === 'win32') {
		shellPath = process.env.ComSpec || 'cmd.exe';
		process.env.Q = '"'; // The quote (") that isn't escaped.
		// `()` for ignore space by echo
		shellArgs = ['/V:ON', '/S', '/C',
			'(%Q%' + shellPath + '%Q% /V:ON /S /C %Q%'
			+ '%Q%' + extHostPath + '%Q%'
			+ hostArgs.map(function (arg) {
				return ' %Q%' + arg + '%Q%';
			}).join('')
			+ ' & (echo !ERRORLEVEL!)>%Q%' + pathExit + '%Q%%Q%) 2>%Q%' + pathStderr + '%Q%'
			+ ' |%Q%' + process.execPath + '%Q% %Q%' + __dirname + '\\encrypt.js%Q%'
			+ ' %Q%' + ALGORITHM_CIPHER + '%Q% %Q%' + password + '%Q%'
			+ ' >%Q%' + pathStdout + '%Q% & (echo 1)>%Q%' + pathDone + '%Q%'];
	}
	else {
		shellPath = '/bin/sh';
		// Use `()`, not `{}` for `-c` (text param)
		shellArgs = ['-c', '("' + extHostPath + '"'
		+ hostArgs.map(function (arg) { return " '" + arg.replace(/'/g, "'\\''") + "'"; }).join('')
		+ '; echo $?>"' + pathExit + '") 2>"' + pathStderr + '"'
		+ ' |"' + process.execPath + '" "' + __dirname + '/encrypt.js"'
		+ ' "' + ALGORITHM_CIPHER + '" "' + password + '" >"' + pathStdout + '"'
		+ '; echo 1 >"' + pathDone + '"'];
	}
	try {
		childProc.spawn(shellPath, shellArgs, execOptions);
	}
	catch (e) {
		res.error = new Error(e.message);
		res.error.method = '_execFileSync - spawn';
		res.error.program = shellPath;
		res.error.args = shellArgs;
	}

	while (fs.readFileSync(pathDone, { encoding: options.encoding }).trim() !== '1') {
		// empty
	}

	exitCode = fs.readFileSync(pathExit, { encoding: options.encoding }).trim();

	if (exitCode === '0') {
		res.input = decipher.update(fs.readFileSync(pathStdout, { encoding: 'binary' }), 'hex', options.encoding);
		res.input += decipher.final(options.encoding);
	}
	else {
		extMessage = fs.readFileSync(pathStderr, { encoding: options.encoding }).trim();
		res.error = new Error(DEFAULT_ERR_MSG + (extMessage ? '\n' + extMessage : ''));
		res.error.method = '_execFileSync';
		res.error.program = shellPath;
		res.error.args = shellArgs;
		res.error.extMessage = extMessage;
		res.error.exitCode = +exitCode;
	}

	fs.unlinkSync(pathStdout);
	fs.unlinkSync(pathStderr);
	fs.unlinkSync(pathExit);
	fs.unlinkSync(pathDone);

	return res;
}

function readlineExt(options) {
	var hostArgs;
	var res = {};
	var extMessage;
	var execOptions = { env: process.env, encoding: options.encoding };

	if (childProc.execFileSync) {
		hostArgs = getHostArgs(options);
		try {
			res.input = childProc.execFileSync(extHostPath, hostArgs, execOptions);
		}
		catch (e) { // non-zero exit code
			extMessage = e.stderr ? (e.stderr + '').trim() : '';
			res.error = new Error(DEFAULT_ERR_MSG + (extMessage ? '\n' + extMessage : ''));
			res.error.method = 'execFileSync';
			res.error.program = extHostPath;
			res.error.args = hostArgs;
			res.error.extMessage = extMessage;
			res.error.exitCode = e.status;
			res.error.code = e.code;
			res.error.signal = e.signal;
		}
	}
	else {
		res = _execFileSync(options, execOptions);
	}
	if (!res.error) {
		res.input = res.input.replace(/^\s*'|'\s*$/g, '');
		options.display = '';
	}

	return res;
}

function isMatched(res, comps, caseSensitive) {
	return comps.some(function (comp) {
		var type = typeof comp;
		return type === 'string' ?
			(caseSensitive ? res === comp : res.toLowerCase() === comp.toLowerCase()) :
			type === 'number' ? parseFloat(res) === comp :
			type === 'function' ? comp(res) :
			comp instanceof RegExp ? comp.test(res) : false;
	});
}

function toBool(res, options) {
	return (
		(options.trueValue.length && isMatched(res, options.trueValue, options.caseSensitive)) ? true :
		(options.falseValue.length && isMatched(res, options.falseValue, options.caseSensitive)) ? false : res);
}

/*
  display:            string
  displayOnly:        boolean
  keyIn:              boolean
  hideEchoBack:       boolean
  mask:               string
  limit:              string (pattern)
  caseSensitive:      boolean
  keepWhitespace:     boolean
  encoding, bufferSize, print
*/
function _readlineSync(options) {
	var input = '';
	var displaySave = options.display;
	var silent = !options.display && options.keyIn && options.hideEchoBack && !options.mask;

	function tryExt() {
		var res = readlineExt(options);
		if (res.error) { throw res.error; }
		return res.input;
	}

	((function () { // open TTY
		var fsB;
		var constants;
		var verNum;

		function getFsB() {
			if (!fsB) {
				fsB = process.binding('fs');
				constants = process.binding('constants');
			}
			return fsB;
		}

		if (typeof fdR !== 'string') { return; }
		fdR = null;

		if (process.platform === 'win32') {
			verNum = ((function (ver) { // getVerNum
				var nums = ver.replace(/^\D+/, '').split('.');
				verNum = 0;

				if ((nums[0] = +nums[0])) {
					verNum += nums[0] * 10000;
				}
				if ((nums[1] = +nums[1])) {
					verNum += nums[1] * 100;
				}
				if ((nums[2] = +nums[2])) {
					verNum += nums[2];
				}

				return verNum;
			})(process.version));

			if (!((verNum >= 20302 && verNum < 40204)
					|| (verNum >= 50000 && verNum < 50100)
					|| (verNum >= 50600 && verNum < 60200))
					&& process.stdin.isTTY) {
				process.stdin.pause();
				fdR = process.stdin.fd;
				ttyR = process.stdin._handle;
			}
			else {
				try {
					// The stream by fs.openSync('\\\\.\\CON', 'r') can't switch to raw mode.
					// 'CONIN$' might fail on XP, 2000, 7 (x86).
					fdR = getFsB().open('CONIN$', constants.O_RDWR, 438);
					ttyR = new TTY(fdR, true);
				}
				catch (e) { /* ignore */ }
			}

			if (process.stdout.isTTY) {
				fdW = process.stdout.fd;
			}
			else {
				try {
					fdW = fs.openSync('\\\\.\\CON', 'w');
				}
				catch (e) { /* ignore */ }

				if (typeof fdW !== 'number') { // Retry
					try {
						fdW = getFsB().open('CONOUT$', constants.O_RDWR, 438);
					}
					catch (e) { /* ignore */ }
				}
			}
		}
		else {
			if (process.stdin.isTTY) {
				process.stdin.pause();
				try {
					fdR = fs.openSync('/dev/tty', 'r'); // device file, not process.stdin
					ttyR = process.stdin._handle;
				}
				catch (e) { /* ignore */ }
			}
			else {
				// Node.js v0.12 read() fails.
				try {
					fdR = fs.openSync('/dev/tty', 'r');
					ttyR = new TTY(fdR, false);
				}
				catch (e) { /* ignore */ }
			}

			if (process.stdout.isTTY) {
				fdW = process.stdout.fd;
			}
			else {
				try {
					fdW = fs.openSync('/dev/tty', 'w');
				}
				catch (e) { /* ignore */ }
			}
		}
	})());

	((function () { // try read
		var atEol;
		var limit;
		var isCooked = !options.hideEchoBack && !options.keyIn;
		var buffer;
		var reqSize;
		var readSize;
		var chunk;
		var line;
		var rawInput = '';

		// Node.js v0.10- returns an error if same mode is set.
		function setRawMode(mode) {
			if (mode === isRawMode) { return true; }
			if (ttyR.setRawMode(mode) !== 0) { return false; }
			isRawMode = mode;
			return true;
		}

		if (!setRawMode(!isCooked)) {
			input = tryExt();
			return;
		}

		reqSize = options.keyIn ? 1 : options.bufferSize;
		// Check `allocUnsafe` to make sure of the new API.
		buffer = Buffer.allocUnsafe && Buffer.alloc ? Buffer.alloc(reqSize) : new Buffer(reqSize);

		if (options.keyIn && options.limit) {
			limit = new RegExp('[^' + options.limit + ']', 'g' + (options.caseSensitive ? '' : 'i'));
		}

		while (true) {
			readSize = 0;
			try {
				readSize = fs.readSync(fdR, buffer, 0, reqSize);
			}
			catch (e) {
				if (e.code !== 'EOF') {
					setRawMode(false);
					input += tryExt();
					return;
				}
			}
			if (readSize > 0) {
				chunk = buffer.toString(options.encoding, 0, readSize);
				rawInput += chunk;
			}
			else {
				chunk = '\n';
				rawInput += String.fromCharCode(0);
			}

			line = (chunk.match(/^(.*?)[\r\n]/) || [])[1];

			if (chunk && typeof (line) === 'string') {
				chunk = line;
				atEol = true;
			}

			// other ctrl-chars
			// eslint-disable-next-line no-control-regex
			if (chunk) { chunk = chunk.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, ''); }
			if (chunk && limit) { chunk = chunk.replace(limit, ''); }

			if (chunk) {
				if (!isCooked) {
					if (!options.hideEchoBack) {
						fs.writeSync(fdW, chunk);
					} else if (options.mask) {
						fs.writeSync(fdW, (new Array(chunk.length + 1)).join(options.mask));
					}
				}
				input += chunk;
			}

			if ((!options.keyIn && atEol) || (options.keyIn && input.length >= reqSize)) {
				break;
			}
		}

		if (!isCooked && !silent) { fs.writeSync(fdW, '\n'); }
		setRawMode(false);
	})());

	if (options.print && !silent) {
		options.print(displaySave + (options.displayOnly ? '' : (options.hideEchoBack ? (new Array(input.length + 1)).join(options.mask) : input) + '\n'), options.encoding);
	}

	return options.displayOnly ? '' : (lastInput = options.keepWhitespace || options.keyIn ? input : input.trim());
}

function read() {
	return toBool(_readlineSync(defaultOptions), defaultOptions);
}

function write(text) {
	process.stdout.write(text);
}

module.exports = {
	read,
	write,
};
