"use strict";

let express  = require('express');
let app      = express();
let helmet = require('helmet');
let compression = require('compression');
let fs       = require("fs");
let morgan   = require("morgan");
let winston = require('winston');
let moment   = require("moment");
let httpProxy = require('http-proxy');
let device = require('express-device');
let envConf = require('../envConfig');
let apiProxy = (envConf[envConf.environmentName].appSSL.enabled ? httpProxy.createProxyServer({ssl : {cert : fs.readFileSync(envConf[envConf.environmentName].appSSL.cert, 'utf8'), key : fs.readFileSync(envConf[envConf.environmentName].appSSL.key, 'utf8')}, secure : false}) : httpProxy.createProxyServer());
let httpProtocol = (envConf[envConf.environmentName].appSSL.enabled ? require("https") : require("http"));

app.use(device.capture({parseUserAgent:true}));
app.use(helmet());
app.use(compression());

let serverLogStream = fs.createWriteStream(__dirname + '/logs/server.log', {flags: 'a'});

/**
* Define server log date format.
**/
morgan.token('date', function(req, res) {
    return moment(new Date()).format("YYYY-MM-DDTHH:mm:ss");
});

/**
* Define server log request headers to be written.
**/
morgan.token('type', function(req, res) {
    return JSON.stringify(req.headers);
});

app.use(morgan(':remote-addr - :remote-user [:date] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" \':type\' - :response-time ms', {stream: serverLogStream}));

let protocol = (envConf[envConf.environmentName].appSSL.enabled ? "https://" : "http://");
let userApi = protocol + 'localhost:3081';
let importService = protocol + 'localhost:3082';

app.use(function(req, res, next) {
        var allowOrigin = req.headers.origin;
        var allowedOrigin = new RegExp(envConf[envConf.environmentName].corsConfig.originRegex);
        var allowedLocalOrigin = new RegExp(envConf[envConf.environmentName].corsConfig.localRegex);
        var ssoOrigin = new RegExp("^(?=.*\/sso\/).+$");

        if(req.headers.authentication !== undefined) {
            var decodedString = new Buffer(req.headers.authentication, 'base64').toString('ascii');
            if((decodedString !== envConf[envConf.environmentName].mobileApp.secretKey) || req.headers["x-requested-with"] === undefined || (req.headers["x-requested-with"] !== envConf[envConf.environmentName].mobileApp.iosIdentifier && req.headers["x-requested-with"] !== envConf[envConf.environmentName].mobileApp.androidIdentifier)) {
                return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
            }
            else {
                //console.log("setting header for mobile---");
                if(allowOrigin)
                 res.setHeader("Access-Control-Allow-Origin", allowOrigin);
            }
        }
        else {
                if(allowOrigin){
                        if(!ssoOrigin.test(req.url) && !allowedOrigin.test(allowOrigin) && (!envConf[envConf.environmentName].corsConfig.allowLocalCors || !allowedLocalOrigin.test(allowOrigin))) {
                                console.log('if false '+allowOrigin);
                                return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
                        }

                        if(allowedOrigin.test(allowOrigin) || (envConf[envConf.environmentName].corsConfig.allowLocalCors && allowedLocalOrigin.test(allowOrigin))){
                                console.log('if true '+allowOrigin);
                                res.setHeader("Access-Control-Allow-Origin", allowOrigin);
                        }
                }
                else {
                        console.log("setting for www");
                        res.setHeader("Access-Control-Allow-Origin",envConf[envConf.environmentName].corsConfig.host);
                }
        }


        res.setHeader("Access-Control-Allow-Credentials", true);
        res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authentication");
        res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE');
        res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        res.setHeader("Pragma", "no-cache");
        next();
});

/**
* Check for valid domain request.
**/
app.use(/^(?!.*\/sso\/).+$/,function(req, res, next) {
    function checkForIP(part) {
        var ip = true;
        var checkIntegerValue = /^\d+$/;
        for (var i = 0; i < part.length; i++) {
            if (!checkIntegerValue.test(part[i])) {
                ip = false;
                break;
            }
        }
        return ip;
    }
    if(envConf.environmentName !== "local") {
        if(req.headers.referer === undefined && req.headers.authentication === undefined) {
            return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
        }
        if(envConf.environmentName !== "development" && req.headers.referer !== undefined) {
            var originName = envConf[envConf.environmentName].protocol + envConf[envConf.environmentName].domain;
            var fullOriginName = originName;
            var origin = (req.headers.origin !== undefined ? req.headers.origin : null);
            if(envConf[envConf.environmentName].domain.split(".")[0] !== "www") {
                fullOriginName = envConf[envConf.environmentName].protocol + "www." + envConf[envConf.environmentName].domain;
            }
            var refererName = req.headers.referer.split("://");
            var refererDomain = refererName[1].split("/")[0];
            var part = refererDomain.split('.').reverse();
            var index = 0;
            var isIPReq = false;
            if (part.length === 4) {
                isIPReq = checkForIP(part);
            }
            if (isIPReq) {
                return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
            }
            while ((part[index] !== undefined && part[index].length === 2) || !index) {
                ++index;
            }
            ++index;
            var subDomain = ((part.length > index && (part[index] !== 'www' && part[index] !== envConf[envConf.environmentName].mainSubDomain)) ? part[index] : "");
            var originProtocol = null;
            var validOrigin = null;
            if(origin !== null) {
                originProtocol = origin.split("://")[0] + "://";
                validOrigin = originProtocol + (subDomain !== "" ? "www." + origin.split(originProtocol)[1].split(subDomain + ".")[1] : (origin.split(originProtocol)[1].split(".")[0] !== "www" ? "www." + origin.split(originProtocol)[1].split(envConf[envConf.environmentName].mainSubDomain + ".")[origin.split(originProtocol)[1].split(envConf[envConf.environmentName].mainSubDomain + ".").length - 1] : origin.split(originProtocol)[1]));
            }
            if(subDomain !== "" && (origin === null || origin.split(originProtocol)[1].split(".")[0] !== subDomain)) {
                return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
            }
            if(subDomain !== "") {
                refererDomain = refererDomain.split(subDomain + ".")[1];
            }
            if(refererDomain.split(".")[0] !== "www") {
                refererDomain = "www." + (refererDomain.split(".")[0] === envConf[envConf.environmentName].mainSubDomain ? refererDomain.split(envConf[envConf.environmentName].mainSubDomain + ".")[1] : refererDomain);
            }
            var refererValue = refererName[0] + "://" + refererDomain;
            if(refererValue !== fullOriginName || (origin !== null && validOrigin !== fullOriginName)) {
                return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
            }
        }
        if(req.headers.authentication !== undefined) {
            var decodedString = new Buffer(req.headers.authentication, 'base64').toString('ascii');
            if(decodedString !== envConf[envConf.environmentName].mobileApp.secretKey) {
                return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
            }
            if(req.headers["x-requested-with"] === undefined || (req.headers["x-requested-with"] !== envConf[envConf.environmentName].mobileApp.iosIdentifier && req.headers["x-requested-with"] !== envConf[envConf.environmentName].mobileApp.androidIdentifier)) {
                return res.status(200).json({"responseCode" : 1, "responseDesc" : "You are not authorized to access"});
            }
        }
    }
    winston.log("info", "Micro Services Called... " + req.url);
    next();
});

app.all("/ms1/*", function(req, res) {
    req.url = req.url.replace("/ms1","");
    apiProxy.web(req, res, {target: userApi, xfwd: true, headers:{"Authorization":envConf[envConf.environmentName].redisConfig.secret,"device" : JSON.stringify(req.device)}},function(error) {
        if(error) {
            return res.json({"responseCode" : 1, "responseDesc" : "Something went wrong with company micro service", "data" : error});
        }
    });
});

app.all("/ms2/*", function(req, res) {
    req.url = req.url.replace("/ms2","");
    apiProxy.web(req, res, {target: importService, xfwd: true, headers:{"Authorization":envConf[envConf.environmentName].redisConfig.secret,"device" : JSON.stringify(req.device)}},function(error) {
        if(error) {
            return res.json({"responseCode" : 1, "responseDesc" : "Something went wrong with user micro service", "data" : error});
        }
    });
});

app.all("*", function(req, res) {
    res.status(404).json({"responseCode" : 1, "responseDesc" : "Sorry, invalid request"});
});

app.use(function(err, req, res, next) {
    winston.log("warn", "UncaughtException is encountered in the API gateway... " + err.stack);
    if (res.headersSent) {
        return next(err);
    }
    res.status(200).json({"responseCode" : 1, "responseDesc" : "Oops, something went wrong, please try again later"});
});

/**
* To start express server with secure connection.
**/
var httpServer = null;
if(envConf[envConf.environmentName].appSSL.enabled) {
    var credentials = null;
    try {
        var certificate = fs.readFileSync(envConf[envConf.environmentName].appSSL.cert, 'utf8');
        var privateKey  = fs.readFileSync(envConf[envConf.environmentName].appSSL.key, 'utf8');
        credentials = {cert : certificate, key : privateKey};
    } catch(e) {
        throw new Error("Error reading the ssl files - " + JSON.stringify(e));
    }
    httpServer = httpProtocol.createServer(credentials, app);
} else {
    httpServer = httpProtocol.createServer(app);
}

/**
* Server start port.
**/
httpServer.listen(3080, function() {
    winston.log("info", "Server started at port..." + 3080 + " on " + new Date());
});