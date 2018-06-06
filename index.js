var fs = require('fs');
var childProc = require('child_process');
var pathUtil = require('path');

var ALGORITHM_CIPHER = 'aes-256-cbc';
var ALGORITHM_HASH = 'sha256';
var DEFAULT_ERR_MSG = 'The current environment doesn\'t support interactive reading from TTY.';
var TTY = process.binding('tty_wrap').TTY;
var defaultOptions = {
  /* eslint-disable key-spacing */
  prompt:             '> ',
  hideEchoBack:       false,
  mask:               '*',
  limit:              [],
  limitMessage:       'Input another, please.$<( [)limit(])>',
  defaultInput:       '',
  trueValue:          [],
  falseValue:         [],
  caseSensitive:      false,
  keepWhitespace:     false,
  encoding:           'utf8',
  bufferSize:         1024,
  print:              void 0,
  history:            true,
  cd:                 false,
  phContent:          void 0,
  preCheck:           void 0
  /* eslint-enable key-spacing */
};
var fdR = 'none';
var fdW;
var ttyR;
var isRawMode = false;
var extHostPath;
var extHostArgs;
var tempdir;
var salt = 0;
var lastInput = '';
var inputHistory = [];
var rawInput;

function getHostArgs(options) {
  // Send any text to crazy Windows shell safely.
  function encodeArg(arg) {
    return arg.replace(/[^\w\u0080-\uFFFF]/g, function(chr) {
      return '#' + chr.charCodeAt(0) + ';';
    });
  }

  return extHostArgs.concat((function() {
    conf = {
      display:        'string',
      displayOnly:    'boolean',
      keyIn:          'boolean',
      hideEchoBack:   'boolean',
      mask:           'string',
      limit:          'string',
      caseSensitive:  'boolean'
    };

    var args = [];

    Object.keys(conf).forEach(function(optionName) {
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

    return args;
  })());
}

// piping via files (for Node.js v0.10-)
function _execFileSync(options, execOptions) {

  function getTempfile(name) {
    var filepath, suffix = '', fd;
    tempdir = tempdir || require('os').tmpdir();

    while (true) {
      filepath = pathUtil.join(tempdir, name + suffix);
      try {
        fd = fs.openSync(filepath, 'wx');
      } catch (e) {
        if (e.code === 'EEXIST') {
          suffix++;
          continue;
        } else {
          throw e;
        }
      }
      fs.closeSync(fd);
      break;
    }
    return filepath;
  }

  var hostArgs, shellPath, shellArgs, res = {}, exitCode, extMessage,
    pathStdout = getTempfile('readline-sync.stdout'),
    pathStderr = getTempfile('readline-sync.stderr'),
    pathExit = getTempfile('readline-sync.exit'),
    pathDone = getTempfile('readline-sync.done'),
    crypto = require('crypto'), shasum, decipher, password;

  shasum = crypto.createHash(ALGORITHM_HASH);
  shasum.update('' + process.pid + (salt++) + Math.random());
  password = shasum.digest('hex');
  decipher = crypto.createDecipher(ALGORITHM_CIPHER, password);

  hostArgs = getHostArgs(options);
  if (process.platform === 'win32') {
    shellPath = process.env.ComSpec || 'cmd.exe';
    process.env.Q = '"'; // The quote (") that isn't escaped.
    // `()` for ignore space by echo
    shellArgs = ['/V:ON', '/S', '/C',
      '(%Q%' + shellPath + '%Q% /V:ON /S /C %Q%' + /* ESLint bug? */ // eslint-disable-line no-path-concat
        '%Q%' + extHostPath + '%Q%' +
          hostArgs.map(function(arg) { return ' %Q%' + arg + '%Q%'; }).join('') +
        ' & (echo !ERRORLEVEL!)>%Q%' + pathExit + '%Q%%Q%) 2>%Q%' + pathStderr + '%Q%' +
      ' |%Q%' + process.execPath + '%Q% %Q%' + __dirname + '\\encrypt.js%Q%' +
        ' %Q%' + ALGORITHM_CIPHER + '%Q% %Q%' + password + '%Q%' +
        ' >%Q%' + pathStdout + '%Q%' +
      ' & (echo 1)>%Q%' + pathDone + '%Q%'];
  } else {
    shellPath = '/bin/sh';
    shellArgs = ['-c',
      // Use `()`, not `{}` for `-c` (text param)
      '("' + extHostPath + '"' + /* ESLint bug? */ // eslint-disable-line no-path-concat
          hostArgs.map(function(arg) { return " '" + arg.replace(/'/g, "'\\''") + "'"; }).join('') +
        '; echo $?>"' + pathExit + '") 2>"' + pathStderr + '"' +
      ' |"' + process.execPath + '" "' + __dirname + '/encrypt.js"' +
        ' "' + ALGORITHM_CIPHER + '" "' + password + '"' +
        ' >"' + pathStdout + '"' +
      '; echo 1 >"' + pathDone + '"'];
  }
  try {
    childProc.spawn(shellPath, shellArgs, execOptions);
  } catch (e) {
    res.error = new Error(e.message);
    res.error.method = '_execFileSync - spawn';
    res.error.program = shellPath;
    res.error.args = shellArgs;
  }

  while (fs.readFileSync(pathDone, {encoding: options.encoding}).trim() !== '1') {} // eslint-disable-line no-empty
  if ((exitCode =
      fs.readFileSync(pathExit, {encoding: options.encoding}).trim()) === '0') {
    res.input =
      decipher.update(fs.readFileSync(pathStdout, {encoding: 'binary'}),
        'hex', options.encoding) +
      decipher.final(options.encoding);
  } else {
    extMessage = fs.readFileSync(pathStderr, {encoding: options.encoding}).trim();
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
  var hostArgs, res = {}, extMessage,
    execOptions = {env: process.env, encoding: options.encoding};

  if (childProc.execFileSync) {
    hostArgs = getHostArgs(options);
    try {
      res.input = childProc.execFileSync(extHostPath, hostArgs, execOptions);
    } catch (e) { // non-zero exit code
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
  } else {
    res = _execFileSync(options, execOptions);
  }
  if (!res.error) {
    res.input = res.input.replace(/^\s*'|'\s*$/g, '');
    options.display = '';
  }

  return res;
}

function isMatched(res, comps, caseSensitive) {
  return comps.some(function(comp) {
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
    (options.trueValue.length &&
      isMatched(res, options.trueValue, options.caseSensitive)) ? true :
    (options.falseValue.length &&
      isMatched(res, options.falseValue, options.caseSensitive)) ? false : res);
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
  var input = '', displaySave = options.display,
    silent = !options.display &&
      options.keyIn && options.hideEchoBack && !options.mask;

  function tryExt() {
    var res = readlineExt(options);
    if (res.error) { throw res.error; }
    return res.input;
  }

  (function() { // open TTY
    var fsB, constants, verNum;

    function getFsB() {
      if (!fsB) {
        fsB = process.binding('fs'); // For raw device path
        constants = process.binding('constants');
      }
      return fsB;
    }

    if (typeof fdR !== 'string') { return; }
    fdR = null;

    if (process.platform === 'win32') {
      // iojs-v2.3.2+ input stream can't read first line. (#18)
      // ** Don't get process.stdin before check! **
      // Fixed v5.1.0
      // Fixed v4.2.4
      // It regressed again in v5.6.0, it is fixed in v6.2.0.
      verNum = (function(ver) { // getVerNum
        var nums = ver.replace(/^\D+/, '').split('.');
        var verNum = 0;
        if ((nums[0] = +nums[0])) { verNum += nums[0] * 10000; }
        if ((nums[1] = +nums[1])) { verNum += nums[1] * 100; }
        if ((nums[2] = +nums[2])) { verNum += nums[2]; }
        return verNum;
      })(process.version);
      if (!(verNum >= 20302 && verNum < 40204 || verNum >= 50000 && verNum < 50100 || verNum >= 50600 && verNum < 60200) &&
          process.stdin.isTTY) {
        process.stdin.pause();
        fdR = process.stdin.fd;
        ttyR = process.stdin._handle;
      } else {
        try {
          // The stream by fs.openSync('\\\\.\\CON', 'r') can't switch to raw mode.
          // 'CONIN$' might fail on XP, 2000, 7 (x86).
          fdR = getFsB().open('CONIN$', constants.O_RDWR, parseInt('0666', 8));
          ttyR = new TTY(fdR, true);
        } catch (e) { /* ignore */ }
      }

      if (process.stdout.isTTY) {
        fdW = process.stdout.fd;
      } else {
        try {
          fdW = fs.openSync('\\\\.\\CON', 'w');
        } catch (e) { /* ignore */ }
        if (typeof fdW !== 'number') { // Retry
          try {
            fdW = getFsB().open('CONOUT$', constants.O_RDWR, parseInt('0666', 8));
          } catch (e) { /* ignore */ }
        }
      }

    } else {
      if (process.stdin.isTTY) {
        process.stdin.pause();
        try {
          fdR = fs.openSync('/dev/tty', 'r'); // device file, not process.stdin
          ttyR = process.stdin._handle;
        } catch (e) { /* ignore */ }
      } else {
        // Node.js v0.12 read() fails.
        try {
          fdR = fs.openSync('/dev/tty', 'r');
          ttyR = new TTY(fdR, false);
        } catch (e) { /* ignore */ }
      }

      if (process.stdout.isTTY) {
        fdW = process.stdout.fd;
      } else {
        try {
          fdW = fs.openSync('/dev/tty', 'w');
        } catch (e) { /* ignore */ }
      }
    }
  })();

  (function() { // try read
    var atEol, limit,
      isCooked = !options.hideEchoBack && !options.keyIn,
      buffer, reqSize, readSize, chunk, line;
    rawInput = '';

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
      limit = new RegExp('[^' + options.limit + ']',
        'g' + (options.caseSensitive ? '' : 'i'));
    }

    while (true) {
      readSize = 0;
      try {
        readSize = fs.readSync(fdR, buffer, 0, reqSize);
      } catch (e) {
        if (e.code !== 'EOF') {
          setRawMode(false);
          input += tryExt();
          return;
        }
      }
      if (readSize > 0) {
        chunk = buffer.toString(options.encoding, 0, readSize);
        rawInput += chunk;
      } else {
        chunk = '\n';
        rawInput += String.fromCharCode(0);
      }

      if (chunk && typeof (line = (chunk.match(/^(.*?)[\r\n]/) || [])[1]) === 'string') {
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

      if (!options.keyIn && atEol ||
        options.keyIn && input.length >= reqSize) { break; }
    }

    if (!isCooked && !silent) { fs.writeSync(fdW, '\n'); }
    setRawMode(false);
  })();

  if (options.print && !silent) {
    options.print(displaySave + (options.displayOnly ? '' :
        (options.hideEchoBack ? (new Array(input.length + 1)).join(options.mask)
          : input) + '\n'), // must at least write '\n'
      options.encoding);
  }

  return options.displayOnly ? '' :
    (lastInput = options.keepWhitespace || options.keyIn ? input : input.trim());
}

function replacePlaceholder(text, generator) {
  var PTN_INNER = '(?:\\(([\\s\\S]*?)\\))?(\\w+|.-.)(?:\\(([\\s\\S]*?)\\))?',
    rePlaceholder = new RegExp('(\\$)?(\\$<' + PTN_INNER + '>)', 'g'),
    rePlaceholderCompat = new RegExp('(\\$)?(\\$\\{' + PTN_INNER + '\\})', 'g');

  function getPlaceholderText(s, escape, placeholder, pre, param, post) {
    var text;
    return escape || typeof (text = generator(param)) !== 'string' ? placeholder :
      text ? (pre || '') + text + (post || '') : '';
  }

  return text.replace(rePlaceholder, getPlaceholderText)
    .replace(rePlaceholderCompat, getPlaceholderText);
}

function read() {
	var res, forceNext, limitMessage, matches, histInput, args, resCheck;

  function _getPhContent(param) { return getPhContent(param, defaultOptions); }
  function addDisplay(text) { defaultOptions.display += (/[^\r\n]$/.test(defaultOptions.display) ? '\n' : '') + text; }

  defaultOptions.limitSrc = defaultOptions.limit;
  defaultOptions.displaySrc = defaultOptions.display;
  defaultOptions.limit = ''; // for readlineExt
  defaultOptions.display = replacePlaceholder(defaultOptions.display + '', _getPhContent);

  while (true) {
    res = _readlineSync(defaultOptions);
    forceNext = false;
    limitMessage = '';

    if (defaultOptions.defaultInput && !res) { res = defaultOptions.defaultInput; }

    if (defaultOptions.history) {
      if ((matches = /^\s*\!(?:\!|-1)(:p)?\s*$/.exec(res))) { // `!!` `!-1` +`:p`
        histInput = inputHistory[0] || '';
        if (matches[1]) { // only display
          forceNext = true;
        } else { // replace input
          res = histInput;
        }
        // Show it even if it is empty (NL only).
        addDisplay(histInput + '\n');
        if (!forceNext) { // Loop may break
          defaultOptions.displayOnly = true;
          _readlineSync(defaultOptions);
          defaultOptions.displayOnly = false;
        }
      } else if (res && res !== inputHistory[inputHistory.length - 1]) {
        inputHistory = [res];
      }
    }

    if (!forceNext && defaultOptions.preCheck) {
      resCheck = defaultOptions.preCheck(res, defaultOptions);
      res = resCheck.res;
      if (resCheck.forceNext) { forceNext = true; } // Don't switch to false.
    }

    if (!forceNext) {
      if (!defaultOptions.limitSrc.length ||
        isMatched(res, defaultOptions.limitSrc, defaultOptions.caseSensitive)) { break; }
      if (defaultOptions.limitMessage) {
        limitMessage = replacePlaceholder(defaultOptions.limitMessage, _getPhContent);
      }
    }

    addDisplay((limitMessage ? limitMessage + '\n' : '') +
      replacePlaceholder(defaultOptions.displaySrc + '', _getPhContent));
  }
  return toBool(res, defaultOptions);
}

function write(text) {
	process.stdout.write(text);
}

module.exports = {
	read,
	write,
};
