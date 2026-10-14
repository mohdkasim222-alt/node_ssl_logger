/*

  node_ssl_logger: Decrypts and logs a process's SSL traffic via Frida Code Injection
  Extended to save captured messages/media to ./outputs/ and keep a metadata index.
  2017, QXIP BV, Lorenzo Mangani <lorenzo.mangani@gmail.com>
  2026, extended by GitHub Copilot Chat Assistant

*/

var frida = require('frida');
var fs = require('fs');
var path = require('path');
var filename = './script.js';
var fsscript;
var debug = false;
var quit = function(code,msg){
	if (msg) console.log(msg)
	process.exit(code ? code : 0);
}

if(process.argv.indexOf("-p") != -1){ var pid = process.argv[process.argv.indexOf("-p") + 1]; }
if(process.argv.indexOf("-v") != -1){ debug = true; }

// outputs directory where captured files will be written
var outputsDir = path.resolve(__dirname, 'outputs');
try { fs.mkdirSync(outputsDir, { recursive: true }); } catch(e) { /* ignore */ }

// metadata index file in outputs
var metadataPath = path.join(outputsDir, 'metadata.json');
function loadMetadata(){
    try {
        var data = fs.readFileSync(metadataPath, 'utf8');
        return JSON.parse(data);
    } catch(e){ return []; }
}
function saveMetadata(meta){
    try {
        fs.writeFileSync(metadataPath, JSON.stringify(meta, null, 2));
    } catch(e){ if (debug) console.error('Failed writing metadata', e); }
}

var seq = 0;

function isLikelyText(buf){
    // Heuristic: check for NUL bytes or a high ratio of non-printable characters
    var len = Math.min(buf.length, 512);
    var nonPrintable = 0;
    for(var i=0;i<len;i++){
        var c = buf[i];
        if (c === 0) return false;
        if (c < 7 || (c>13 && c<32)) nonPrintable++;
    }
    return (nonPrintable / len) < 0.1;
}

function detectExtension(buf, maybeText){
    if(!buf || buf.length < 4) return maybeText ? 'txt' : 'bin';
    // JPEG
    if (buf[0] === 0xFF && buf[1] === 0xD8) return 'jpg';
    // PNG
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return 'png';
    // GIF
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) return 'gif';
    // MP4/ISO media: look for 'ftyp' in first 64 bytes
    var head = buf.slice(0, 64).toString('ascii');
    if (head.indexOf('ftyp') !== -1) return 'mp4';
    // WebM/Matroska: 'matroska' or 'webm' markers
    if (head.indexOf('webm') !== -1 || head.indexOf('matroska') !== -1) return 'webm';
    // PDF
    if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) return 'pdf';

    if (maybeText) {
        // try JSON
        try {
            var s = buf.toString('utf8');
            JSON.parse(s);
            return 'json';
        } catch(e) { return 'txt'; }
    }
    return 'bin';
}

try {
      fs.readFile(filename, function read(err, data) {
        if (!err) {
		fsscript = data.toString();
        } else { quit(1,err); }
      });
} catch(e) { quit(1,'Failed loading script!'); }

if (!pid){ process.exit(1);} 
frida.attach(pid)
.then(function (session) {
  if (debug) console.log('attached:', session);
  return session.createScript(fsscript);
})
.then(function (script) {
  if(debug) { console.log('script created:', script); }
  console.log('Press Ctrl+C to stop logging...');
  script.events.listen('message', function (message, data) {
    if(data && data.length > 0) {
        if (debug) console.log('message from script:', message );
        // attempt to determine if buffer is text
        var maybeText = isLikelyText(data);
        var ext = detectExtension(data, maybeText);
        var ts = (new Date()).toISOString().replace(/[:.]/g,'-');
        seq++;
        var filenameOut = ts + '_' + (seq) + '.' + ext;
        var fullpath = path.join(outputsDir, filenameOut);
        try {
            // write raw buffer
            fs.writeFileSync(fullpath, data);
            // update metadata
            var meta = loadMetadata();
            var entry = {
                filename: filenameOut,
                path: './outputs/' + filenameOut,
                size: data.length,
                timestamp: (new Date()).toISOString(),
                source: message && message.payload ? message.payload : message,
                ext: ext
            };
            meta.unshift(entry);
            // keep only recent 1000 entries to avoid huge metadata files
            if (meta.length > 1000) meta = meta.slice(0,1000);
            saveMetadata(meta);
        } catch(e){
            console.error('Failed writing captured data to file:', e);
        }
        // still print to stdout for backwards compatibility
        try { console.log(data.toString('utf8')); } catch(e) { if(debug) console.log('non-utf8 data'); }
    }
  });
  script.load();
})
.catch(function (error) {
  console.log('error:', error.message);
});
