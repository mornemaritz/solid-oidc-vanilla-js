
// Configure your application and authorization server details
const config = {
    web_id: "https://mornemaritz.solidcommunity.net/profile/card#me",
    // client_id: "https://app.mornemaritz.tech/myappid#this",
    client_id: "e26bc368528ffcf1933b609e30807240",
    client_secret: "b8809bb453a3248cae56bce35a57f2d5",
    redirect_uri: "http://localhost:1234/",
    requested_scopes: "openid offline_access",
    // authorization_endpoint: "https://login.inrupt.com/authorization",
    // token_endpoint: "https://login.inrupt.com/token",
    authorization_endpoint: "https://solidcommunity.net/authorize",
    token_endpoint: "https://solidcommunity.net/token"
  };
  
  /*
Based on https://solidproject.org/TR/oidc-primer
Written using a Combination of 
https://coolaj86.com/articles/sign-jwt-webcrypto-vanilla-js/
https://github.com/aaronpk/pkce-vanilla-js/blob/master/index.html
*/
//////////////////////////////////////////////////////////////////////
// OAUTH REQUEST
// Initiate the PKCE Auth Code flow when the link is clicked
document.getElementById("start").addEventListener("click", async function(e){
    e.preventDefault();

    // Create and store a random "state" value
    var state = generateRandomString();
    localStorage.setItem("pkce_state", state);

    // Step 4
    // Create and store a new PKCE code_verifier (the plaintext random secret)
    var code_verifier = generateRandomString();
    // Step 5
    localStorage.setItem("pkce_code_verifier", code_verifier);

    // Step 4
    // Hash and base64-urlencode the secret to use as the challenge
    var code_challenge = await pkceChallengeFromVerifier(code_verifier);
    // Step 5
    localStorage.setItem("pkce_code_challenge", code_challenge);

    // Build the authorization URL
    var url = config.authorization_endpoint 
    + "?response_type=code"
    + "&client_id="+encodeURIComponent(config.client_id)
    + "&state="+encodeURIComponent(state)
    + "&scope="+encodeURIComponent(config.requested_scopes)
    + "&redirect_uri="+encodeURIComponent(config.redirect_uri)
    + "&code_challenge="+encodeURIComponent(code_challenge)
    + "&code_challenge_method=S256"
    ;
    
    // Step 6
    // Redirect to the authorization server
    window.location = url;
});

function parseQueryString(string) {
    if(string == "") { return {}; }
    var segments = string.split("&").map(s => s.split("=") );
    var queryString = {};
    segments.forEach(s => queryString[s[0]] = s[1]);
    return queryString;
}

//////////////////////////////////////////////////////////////////////
// PKCE HELPER FUNCTIONS

// Generate a secure random string using the browser crypto functions
function generateRandomString() {
    var array = new Uint32Array(28);
    window.crypto.getRandomValues(array);
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}

// Calculate the SHA256 hash of the input text. 
// Returns a promise that resolves to an ArrayBuffer
async function sha256(plainText) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plainText);
    return await window.crypto.subtle.digest('SHA-256', data);
}

// Base64-urlencodes the input string
function base64urlencode(string) {
    // btoa accepts chars only within ascii 0-255 and base64 encodes them.
    // Then convert the base64 encoded to base64url encoded
    //   (replace + with -, replace / with _, trim trailing =)
    return btoa(string)
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Return the base64-urlencoded sha256 hash for the PKCE challenge
async function pkceChallengeFromVerifier(v) {
    const hashed = await sha256(v);
    // Convert the ArrayBuffer to string using Uint8 array to convert to what btoa accepts.
    let stringyfiedHash = String.fromCharCode.apply(null, new Uint8Array(hashed))
    return base64urlencode(stringyfiedHash);
}

var JWT = {};
JWT.sign = async (jwk, headers, claims) => {
    // Make a shallow copy of the key
    // (to set ext if it wasn't already set)
    jwk = Object.assign({}, jwk);

    // The headers should probably be empty
    // headers.typ = 'JWT';
    headers.typ = 'dpop+jwt';
    headers.alg = 'ES256';
    if (!headers.kid) {
        // alternate: see thumbprint function below
        headers.jwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    }

    var jws = {
        // JWT "headers" really means JWS "protected headers"
        protected: strToUrlBase64(JSON.stringify(headers)),

        // JWT "claims" are really a JSON-defined JWS "payload"
        payload: strToUrlBase64(JSON.stringify(claims))
    };

    // To import as EC (ECDSA, P-256, SHA-256, ES256)
    var keyType = {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: { name: 'SHA-256' }
    };

    // To make re-exportable as JSON (or DER/PEM)
    var exportable = true;

    // Import as a private key that isn't black-listed from signing
    var privileges = ['sign'];

    // Actually do the import, which comes out as an abstract key type
    return await window.crypto.subtle
        .importKey('jwk', jwk, keyType, exportable, privileges)
        .then(async privkey => {
            // Convert UTF-8 to Uint8Array ArrayBuffer
            var data = strToUint8(jws.protected + '.' + jws.payload);

            // The signature and hash should match the bit-entropy of the key
            // https://tools.ietf.org/html/rfc7518#section-3
            var sigType = { name: 'ECDSA', hash: { name: 'SHA-256' } };

            return await window.crypto.subtle.sign(sigType, privkey, data)
            .then(signature => {
                // returns an ArrayBuffer containing a JOSE (not X509) signature,
                // which must be converted to Uint8 to be useful
                jws.signature = uint8ToUrlBase64(new Uint8Array(signature));

                // JWT is just a "compressed", "protected" JWS
                return jws.protected + '.' + jws.payload + '.' + jws.signature;
            });
        });
};

var EC = {};
EC.generate = async () => {
    var keyType = {
        name: 'ECDSA',
        namedCurve: 'P-256'
    };
    var exportable = true;
    var privileges = ['sign', 'verify'];
    return await window.crypto.subtle.generateKey(keyType, exportable, privileges)
    .then(async key => {
        // returns an abstract and opaque WebCrypto object,
        // which in most cases you'll want to export as JSON to be able to save
        return await window.crypto.subtle.exportKey('jwk', key.privateKey);
    });
};

// Create a Public Key from a Private Key
//
// chops off the private parts
EC.neuter = jwk => {
    var copy = Object.assign({}, jwk);
    delete copy.d;
    copy.key_ops = ['verify'];
    return copy;
};

var JWK = {};
JWK.thumbprint = async jwk => {
    // lexigraphically sorted, no spaces
    var sortedPub = '{"crv":"CRV","kty":"EC","x":"X","y":"Y"}'
        .replace('CRV', jwk.crv)
        .replace('X', jwk.x)
        .replace('Y', jwk.y);

    // The hash should match the size of the key,
    // but we're only dealing with P-256
    return await window.crypto.subtle
        .digest({ name: 'SHA-256' }, strToUint8(sortedPub))
        .then(hash => {
            return uint8ToUrlBase64(new Uint8Array(hash));
        });
};

// String (UCS-2) to Uint8Array
//
// because... JavaScript, Strings, and Buffers
function strToUint8(str) {
    return new TextEncoder().encode(str);
}

// UCS-2 String to URL-Safe Base64
//
// btoa doesn't work on UTF-8 strings
function strToUrlBase64(str) {
    return binToUrlBase64(utf8ToBinaryString(str));
}

// Binary String to URL-Safe Base64
//
// btoa (Binary-to-Ascii) means "binary string" to base64
function binToUrlBase64(bin) {
    return btoa(bin)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+/g, '');
}

// UTF-8 to Binary String
//
// Because JavaScript has a strange relationship with strings
// https://coolaj86.com/articles/base64-unicode-utf-8-javascript-and-you/
function utf8ToBinaryString(str) {
    var escstr = encodeURIComponent(str);
    // replaces any uri escape sequence, such as %0A,
    // with binary escape, such as 0x0A
    var binstr = escstr.replace(/%([0-9A-F]{2})/g, function(match, p1) {
        return String.fromCharCode(parseInt(p1, 16));
    });

    return binstr;
}

// Uint8Array to URL Safe Base64
//
// the shortest distant between two encodings... binary string
function uint8ToUrlBase64(uint8) {
    var bin = '';
    uint8.forEach(function(code) {
        bin += String.fromCharCode(code);
    });
    return binToUrlBase64(bin);
}


//////////////////////////////////////////////////////////////////////
// OAUTH REDIRECT HANDLING

// Handle the redirect back from the authorization server and
// get an access token from the token endpoint
    
(async ()=>{
    var q = parseQueryString(window.location.search.substring(1));
    
    // Check if the server returned an error string
    if(q.error) {
        alert("Error returned from authorization server: "+q.error);
        document.getElementById("error_details").innerText = q.error+"\n\n"+q.error_description;
        document.getElementById("error").classList = "";
    }

    // If the server returned an authorization code, attempt to exchange it for an access token      
    if(q.code) {
        
        // Verify state matches what we set at the beginning
        if(localStorage.getItem("pkce_state") != q.state) {
            alert("Invalid state");
        } else {
            // tokenBody
            let claims = {
                "htu": config.token_endpoint,
                "htm": "POST",
                "jti": generateRandomString(),
                "iat": Math.round(Date.now() / 1000)
            }
        
            // Step 12. Generates a DPoP Client Key Pair
            // https://solidproject.org/TR/oidc-primer#authorization-code-pkce-flow-step-12
        
            // Step 13. Generates a DPoP Header 
            // https://solidproject.org/TR/oidc-primer#authorization-code-pkce-flow-step-13
            // var dpopHeader = await generateDpopHeader();
            var dpopHeader = await EC.generate()
            .then(async jwk => {
                console.info('Private Key:', JSON.stringify(jwk));
                console.info('Public Key:', JSON.stringify(EC.neuter(jwk)));
                const thumbprint = await JWK.thumbprint(jwk);

                return { jwk, thumbprint }
            })
            .then(async x => {
                // return JWT.sign(jwk, { kid: kid }, claims)
                return await JWT.sign(x.jwk, {}, claims)
            })
            .then(singedJwt => {
                console.info('JWT:', singedJwt);
                
                return singedJwt;
            })
            .catch(e => {
                console.error(e);
                
                document.getElementById("error_details").innerText = error.error+"\n\n"+error.error_description;
                document.getElementById("error").classList = "";
            });    
            
            localStorage.setItem('dpopHeader', dpopHeader);

            const params = {
                grant_type: "authorization_code",
                code: q.code,
                client_id: config.client_id,
                redirect_uri: config.redirect_uri,
                code_verifier: localStorage.getItem("pkce_code_verifier")
            }

            await fetch(config.token_endpoint, {
                method: 'POST',
                headers: {
                    'DPoP': dpopHeader,
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Authorization': 'Basic ' + btoa(config.client_id + ":" + config.client_secret)
                },
                body: Object.keys(params).map(key => key + '=' + params[key]).join('&')
            })
            .then(async response => {
                if (!response.ok) {
                    if(response.status < 500)
                    {
                        const errorResponse = await response.json();
                        throw errorResponse;
                    }
                } 
                return await response.json()
            })
            .then(responseJson => {
                // Initialize your application now that you have an access token.
                // Here we just display it in the browser.
                document.getElementById("access_token").innerText = responseJson.access_token;
                document.getElementById("start").classList = "hidden";
                document.getElementById("token").classList = "";
                
                document.getElementById("pkce_code_verifier").innerText = localStorage.getItem("pkce_code_verifier");
                document.getElementById("code_verifier").classList = "";
                
                document.getElementById("pkce_code_challenge").innerText = localStorage.getItem("pkce_code_challenge");
                document.getElementById("code_challenge").classList = "";
                
                // Replace the history entry to remove the auth code from the browser address bar
                window.history.replaceState({}, null, "/");
            })
            .catch(e => {
                console.error(e);

                document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
                document.getElementById("error").classList = "";

            });
        }
    }

})();
