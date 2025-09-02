/// <reference path="crypto-js.ts" />
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { CryptoJS } from "./crypto-js.js";
var WordArray = CryptoJS.Library.WordArray;
var Base64 = CryptoJS.Encodings.Base64;
export var Auth;
(function (Auth) {
    const loginFailedPrefix = "login failed: ";
    function Authenticate(username, password, logError) {
        return __awaiter(this, void 0, void 0, function* () {
            let random = "";
            while (random.length < 20) {
                let num = Math.trunc(Math.random() * (127 - 33)) + 33;
                if (num != 44) {
                    random = random.concat(String.fromCharCode(num));
                }
            }
            const scramData = { authMessage: "n,,n=" + username + ",r=" + random, random: random, salt: new WordArray(), iterations: 0 };
            let response = yield fetch("./auth", {
                method: "POST",
                headers: [["Authorization", "SCRAM-SHA-256 realm=\"\",data=" + btoa(scramData.authMessage)]]
            });
            if (response.redirected) {
                window.location.assign(response.url);
                return;
            }
            if (response.status != 401) {
                console.error(loginFailedPrefix, response.status, response.statusText);
                logError(response.statusText);
                return;
            }
            let authResponse = response.headers.get("WWW-Authenticate");
            if (!authResponse) {
                let msg = "no authentication method returned by server";
                console.log(loginFailedPrefix, msg);
                logError(msg);
                return;
            }
            let saltedPassword;
            let splitIndex = authResponse.indexOf(" ");
            if (splitIndex == -1) {
                const msg = "bad response from server";
                console.log(loginFailedPrefix, msg);
                logError(msg);
                return;
            }
            const method = authResponse.substring(0, splitIndex).toUpperCase();
            if (method == "BASIC") {
                saltedPassword = CryptoJS.SHA256(password);
                yield basicAuth(username, saltedPassword.toString(Base64), logError);
            }
            else {
                if (method != "SCRAM-SHA-256") {
                    console.log(loginFailedPrefix, authResponse);
                    logError("unsupported authentication method returned by server");
                    return;
                }
                const badResponseMsg = "received bad response from server";
                let parsedResponse = getIdAndData(authResponse.substring(splitIndex + 1));
                const id = parsedResponse.id;
                let data = parsedResponse.data;
                if (id == "" && data == "") {
                    const msg = "username or password invalid";
                    console.log(loginFailedPrefix, msg);
                    logError(msg);
                    return;
                }
                if (id == "" || data == "") {
                    console.log(loginFailedPrefix, authResponse);
                    logError(badResponseMsg);
                    return;
                }
                const firstResponse = atob(data);
                scramData.authMessage += "," + firstResponse;
                const parameters = getParameters(firstResponse);
                for (const parameter of parameters) {
                    switch (parameter.name) {
                        case "r":
                            scramData.random = parameter.value;
                            break;
                        case "s":
                            scramData.salt = Base64.parse(parameter.value);
                            break;
                        case "i":
                            let value = Number(parameter.value);
                            if (Number.isNaN(value)) {
                                console.log(loginFailedPrefix, firstResponse);
                                logError(badResponseMsg);
                                return;
                            }
                            scramData.iterations = value;
                    }
                }
                let invalidResponseMsg = "received invalid response from server";
                if (!scramData.random.startsWith(random) || scramData.salt.sigBytes == 0 || Number.isNaN(scramData.iterations)) {
                    console.error(loginFailedPrefix, firstResponse, "client-random=" + random);
                    logError(invalidResponseMsg);
                    return;
                }
                const cfg = {
                    hasher: new CryptoJS.Algorithms.SHA256(),
                    keySize: 8,
                    iterations: scramData.iterations
                };
                saltedPassword = CryptoJS.PBKDF2(password, scramData.salt, cfg);
                const clientKey = CryptoJS.HmacSHA256("Client Key", saltedPassword);
                const storedKey = CryptoJS.SHA256(clientKey);
                const finalMessage = "c=" + btoa("n,") + ",r=" + scramData.random;
                const clientSignature = CryptoJS.HmacSHA256(scramData.authMessage + "," + finalMessage, storedKey);
                const proof = new WordArray(new Array(clientKey.words.length));
                for (let i = 0; i < clientKey.words.length; i++) {
                    proof.words[i] = clientKey.words[i] ^ clientSignature.words[i];
                }
                response = yield fetch("./auth", {
                    method: "POST",
                    headers: [["Authorization", "SCRAM-SHA-256 sid=" + id + ",data=" + btoa(finalMessage + ",p=" + proof.toString(Base64))]]
                });
                if (response.redirected) {
                    window.location.assign(response.url);
                }
                else if (response.ok) {
                    let authenticationInfo = response.headers.get("Authentication-Info");
                    if (!authenticationInfo) {
                        console.error(loginFailedPrefix, "no Authentication-Info header");
                        logError(invalidResponseMsg);
                        return;
                    }
                    parsedResponse = getIdAndData(authenticationInfo);
                    if (parsedResponse.id != id || !parsedResponse.data) {
                        console.error(loginFailedPrefix, authenticationInfo, "client-id=" + id);
                        logError(invalidResponseMsg);
                    }
                    const serverKey = CryptoJS.HmacSHA256("Server Key", saltedPassword);
                    const serverSignature = CryptoJS.HmacSHA256(scramData.authMessage, serverKey);
                    if (atob(parsedResponse.data) != "v=" + serverSignature.toString(Base64)) {
                        console.log(loginFailedPrefix, atob(parsedResponse.data));
                        logError("server failed to prove its identity");
                        return;
                    }
                }
                else if (response.status == 401) {
                    const msg = "username or password incorrect";
                    console.log(loginFailedPrefix, msg);
                    logError(msg);
                }
                else {
                    console.log(loginFailedPrefix, response.status, response.statusText);
                    logError(response.statusText);
                }
            }
        });
    }
    Auth.Authenticate = Authenticate;
    function basicAuth(username, password, logError) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield fetch("./auth", {
                method: "POST",
                headers: [["Authorization", "BASIC " + atob(username + ":" + password)]]
            });
            if (response.redirected) {
                window.location.assign(response.url);
            }
            else if (!response.ok) {
                console.error(loginFailedPrefix, response.status, response.statusText);
                logError(response.statusText);
            }
        });
    }
    function getParameters(str) {
        let result = [];
        let start = 0;
        let endIndex = str.indexOf(",");
        for (let param = str.substring(start, endIndex); endIndex > -1; param = str.substring(start, endIndex)) {
            const splitIndex = param.indexOf("=");
            if (splitIndex < 1 || splitIndex == param.length - 1) {
                start = endIndex + 1;
                endIndex = str.indexOf(",", start);
                continue;
            }
            result.push({ name: param.substring(0, splitIndex), value: param.substring(splitIndex + 1) });
            start = endIndex + 1;
            endIndex = str.indexOf(",", start);
        }
        const param = str.substring(start);
        const splitIndex = param.indexOf("=");
        if (splitIndex < 1 || splitIndex == param.length - 1) {
            return result;
        }
        result.push({ name: param.substring(0, splitIndex), value: param.substring(splitIndex + 1) });
        return result;
    }
    function getIdAndData(str) {
        let parameters = getParameters(str);
        let id = "";
        let data = "";
        for (const parameter of parameters) {
            switch (parameter.name) {
                case "sid":
                    id = parameter.value;
                    break;
                case "data":
                    data = parameter.value;
                    break;
            }
        }
        return { id, data };
    }
    {
        const loginForm = document.getElementById("loginForm");
        if (loginForm == null) {
            console.error("login form could not be found");
        }
        else {
            loginForm.addEventListener("submit", loginFormSubmit);
        }
    }
    function loginFormSubmit(event) {
        event.preventDefault();
        const overlay = document.getElementById("overlay");
        if (overlay) {
            overlay.style.removeProperty("display");
        }
        if (!(this instanceof HTMLFormElement)) {
            console.error("login called on invalid object " + typeof this);
            return;
        }
        let messageField = document.getElementById("error");
        const showError = function (message) {
            if (messageField instanceof HTMLOutputElement) {
                if (messageField.parentElement) {
                    messageField.parentElement.style.removeProperty("display");
                }
                messageField.innerText = message;
            }
        };
        const inputs = this.querySelectorAll("input");
        let username = "";
        let password = "";
        for (const input of inputs) {
            if (input.name == "name") {
                username = input.value;
            }
            if (input.name == "password") {
                password = input.value;
            }
        }
        username = username.normalize();
        if (username == "" || password == "") {
            showError("Invalid username or password");
            return;
        }
        Auth.Authenticate(username, password, showError).then(() => {
            const overlay = document.getElementById("overlay");
            if (overlay) {
                overlay.style.setProperty("display", "none");
            }
        }).catch(reason => {
            if (reason) {
                showError(reason);
            }
            const overlay = document.getElementById("overlay");
            if (overlay) {
                overlay.style.setProperty("display", "none");
            }
        });
    }
})(Auth || (Auth = {}));
