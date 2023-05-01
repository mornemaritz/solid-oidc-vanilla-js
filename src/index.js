import { Parser } from 'n3';
// Configure your application and authorization server details
const config = {
    web_id: "https://id.inrupt.com/mornemaritz",
    resource_uri: "https://storage.inrupt.com/4ba483d1-894b-4156-856f-5ce1c7efad4d/profile", 
    // web_id: "https://mornemaritz.solidcommunity.net/profile/card#me",
    // resource_uri: "https://mornemaritz.solidcommunity.net/private",
    redirect_uri: "http://localhost:1234/",
    requested_scopes: "openid offline_access"
  };

const client_config = {
	client_name:"https://app.mornemaritz.tech/myappid#this",
	application_type:"web",
	redirect_uris: [
		"http://localhost:1234/"
	],
	subject_type:"public",
	token_endpoint_auth_method:"client_secret_basic",
	id_token_signed_response_alg:"RS256",
	grant_types:[
		"authorization_code",
		"refresh_token"
	]
}

    document.getElementById("getWebIdDocument").addEventListener("click", async e => {
        e.preventDefault();

        await fetch(config.web_id)
        .then(async response => {
            if (!response.ok) {
                if(response.status < 500)
                {
                    const errorResponse = await response.json();
                    throw errorResponse;
                }
            } 
            return await response.text()
        })
        .then(responseText => {
            var parser = new Parser();
            parser.parse(responseText,
                (err,quad,prefixes) => {
                    
                    if (quad) {
                        console.log(quad.object.value);
                        console.log(quad.predicate.value);
    
                        if (quad.predicate.id == "http://www.w3.org/ns/solid/terms#oidcIssuer") {
                            localStorage.setItem("solid_oidc_issuer", quad.object.value)
                            document.getElementById("solid_oidc_issuer").innerText = quad.object.value;
                            document.getElementById("solid_oidc_issuer_div").classList = "";
                        }
                    } else if (err) {
                        console.error(err);
                    } else {
                        console.log("Prefixes", prefixes);
                    }
                })
        })
        .catch(e => {
            console.error(e);

            document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
            document.getElementById("error").classList = "";

        });
    })
    
    document.getElementById("getOpConfiguration").addEventListener("click", async e => {
        e.preventDefault();

        var openidConfiguration = `${localStorage.getItem("solid_oidc_issuer")}/.well-known/openid-configuration`;
        
        await fetch(openidConfiguration)
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
        .then(oidConfig => {
            console.log(oidConfig);
            localStorage.setItem("authorization_endpoint", oidConfig.authorization_endpoint);
            localStorage.setItem("token_endpoint", oidConfig.token_endpoint);
            localStorage.setItem("registration_endpoint", oidConfig.registration_endpoint);

            document.getElementById("authorization_endpoint").innerText = oidConfig.authorization_endpoint;
            document.getElementById("authorization_endpoint_div").classList = "";
            
        })
        .catch(e => {
            console.error(e);

            document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
            document.getElementById("error").classList = "";

        });
    })

    document.getElementById("registerClient").addEventListener("click", async e => {
        e.preventDefault();

        await fetch(localStorage.getItem("registration_endpoint"), {
            method: 'POST',
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(client_config)
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
        .then(clientRegistrationResponse => {
            console.log(clientRegistrationResponse);
            localStorage.setItem("client_id", clientRegistrationResponse.client_id);
            localStorage.setItem("client_secret", clientRegistrationResponse.client_secret);

            document.getElementById("client_id").innerText = clientRegistrationResponse.client_id;
            document.getElementById("client_id_div").classList = "";
            
        })
        .catch(e => {
            console.error(e);

            document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
            document.getElementById("error").classList = "";

        });
    })


    document.getElementById("discoverResourceAuthServer").addEventListener("click", async e => {
        e.preventDefault();

        await fetch(config.resource_uri)
        .then(async response => {
            if (!response.ok) {
                if(response.status == 401) {
                    let rs_auth_server = parseWwwAuthenticateHeader(response.headers.get('www-authenticate'));
                    console.log(rs_auth_server);
                    localStorage.setItem('rs_auth_server', JSON.stringify(rs_auth_server));

                    document.getElementById("resource_auth_server").innerText = rs_auth_server.as_url;
                    document.getElementById("resource_auth_server_div").classList = "";
                }
                else if(response.status < 500)
                {
                    const errorResponse = await response.json();
                    throw errorResponse;
                }
            } 
            return await response.json()
        })
        .catch(e => {
            console.error(e);

            document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
            document.getElementById("error").classList = "";

        });
        
    })

    document.getElementById('requestAuthServerConfig').addEventListener("click", async e => {
        e.preventDefault();

        await requestAuthServerConfig(JSON.parse(localStorage.getItem('rs_auth_server')))    
        .then(uma_config => {
            document.getElementById("as_token_endpoint").innerText = uma_config.token_endpoint;
            document.getElementById("as_token_endpoint_div").classList = "";
        })
        .catch(e => {
            console.error(e);

            document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
            document.getElementById("error").classList = "";
        });
    })

    document.getElementById('requestResourceAccessToken').addEventListener('click', async e => {
        e.preventDefault();

        await requestResourceAccessToken(JSON.parse(localStorage.getItem("uma_config")), JSON.parse(localStorage.getItem('rs_auth_server')))
        .then(responseJson => {
            document.getElementById("resource_access_token").innerText = responseJson.access_token;
            document.getElementById("resource_access_token_div").classList = "";

            // Replace the history entry to remove the auth code from the browser address bar
            window.history.replaceState({}, null, "/");
        })
        .catch(e => {
            console.error(e);

            document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
            document.getElementById("error").classList = "";

        });
    })

    document.getElementById('viewResource').addEventListener('click', async e => {
        e.preventDefault();

        let claims = {
            "htu": config.resource_uri,
            "htm": "GET",
            "jti": generateRandomString(),
            "iat": Math.round(Date.now() / 1000)
        }

        await generateDpopHeader(claims)
        .then(async resourceDPoPHeader => {
            return await fetch(config.resource_uri, {
                headers : {
                    'Authorization': `DPoP ${localStorage.getItem('user_access_token')}`,
                    'DPoP': `${resourceDPoPHeader}`
                }
            })
        })
        .then(async response => {
            if (!response.ok) {
                if(response.status < 500)
                {
                    const errorResponse = await response.json();
                    throw errorResponse;
                }
            } 
            return await response.text()
        })
        .then(responseText => {
            var parser = new Parser();
            parser.parse(responseText,
                (err,quad,prefixes) => {
                    
                    if (quad) {
                        console.log(quad.object.value);
                        console.log(quad.predicate.value);
                    } else if (err) {
                        console.error(err);
                    } else {
                        console.log("Prefixes", prefixes);
                    }
                })
        })
        .catch(e => {
            console.error(e);

            document.getElementById("error_details").innerText = e.error+"\n\n"+e.error_description;
            document.getElementById("error").classList = "";

        });

    })
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
    var url = localStorage.getItem("authorization_endpoint")
    + "?response_type=code"
    + "&client_id="+encodeURIComponent(localStorage.getItem("client_id"))
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

function parseWwwAuthenticateHeader(wwwAuthenticateHeader){
    console.log(`wwwAuthenticateHeader: ${wwwAuthenticateHeader}`);
    let tokens = wwwAuthenticateHeader.split(',');
    let resourceServerAuthConfig = tokens[0].split(' ');
    if (resourceServerAuthConfig[0].toLowerCase() != 'uma') {
        throw new Error(`wwwAuthenticateHeader not UMA: ${resourceServerAuthConfig[0].toLowerCase()}`);
    }    
    
    let authTicket = tokens[1].split('=');

    return {
        as_url: resourceServerAuthConfig[1].split('=')[1].replaceAll('"',''),
        ticket : authTicket[1].replaceAll('"',''),
        auth_types: tokens[2].split(' ').map(s => s.replaceAll('"','')),
        dpop_algs: tokens[3].split('=')[1].split(' ').map(s => s.replaceAll('"',''))
    }
}

async function requestAuthServerConfig(rs_auth_server) {

    if(!rs_auth_server) {
        throw new Error("rs_auth_server not specified");
    }

    return await fetch(`${rs_auth_server.as_url}/.well-known/uma2-configuration`)
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
    .then(uma_config => {
        localStorage.setItem("uma_config", JSON.stringify(uma_config));

        return uma_config;
    })
}

async function requestResourceAccessToken(uma_config, rs_auth_server) {
    if(!uma_config) {
        throw new Error("uma_config not specified");
    }

    if (!rs_auth_server) {
        throw new Error("rs_auth_server not specified");
    }

    // tokenBody
    let claims = {
        "htu": uma_config.token_endpoint,
        "htm": "POST",
        "jti": generateRandomString(),
        "iat": Math.round(Date.now() / 1000)
    }

    const params = {
        grant_type: encodeURIComponent(uma_config.grant_types_supported[0]),
        ticket: rs_auth_server.ticket,
        claim_token: localStorage.getItem("user_access_token"),
        claim_token_format: encodeURIComponent(uma_config.uma_profiles_supported[1]) 
    }

    var resourceDPoPHeader = await generateDpopHeader(claims);
    localStorage.setItem('resource_dpop_header', resourceDPoPHeader);

    return await fetch(uma_config.token_endpoint, {
        method: 'POST',
        headers: {
            'DPoP': resourceDPoPHeader,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Authorization': 'Basic ' + btoa(localStorage.getItem("client_id") + ":" + localStorage.getItem("client_secret"))
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

        localStorage.setItem('resource_access_token', responseJson.access_token);

        return responseJson;
    })
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

async function generateDpopHeader(claims) {
    
    return await getGenerateJsonWebKeyAndThumbprint() 
    .then(async jwkAndThumbprint => {
        // return JWT.sign(jwk, { kid: kid }, claims)
        return await JWT.sign(jwkAndThumbprint.jwk, {}, claims)
    })
    .then(singedJwt => {
        console.info('JWT:', singedJwt);
        
        return singedJwt;
    })
}

async function getGenerateJsonWebKeyAndThumbprint() {
    const json_web_key_and_thumbprint = localStorage.getItem('json_web_key_and_thumbprint');
    if (json_web_key_and_thumbprint) {
        return JSON.parse(json_web_key_and_thumbprint);
    } else {
        return await EC.generate()
        .then(async jwk => {
            console.info('Private Key:', JSON.stringify(jwk));
            console.info('Public Key:', JSON.stringify(EC.neuter(jwk)));
    
            const thumbprint = await JWK.thumbprint(jwk);
            const jsonWebKeyAndThumbprint = { jwk, thumbprint }
            localStorage.setItem('json_web_key_and_thumbprint', JSON.stringify(jsonWebKeyAndThumbprint));
    
            return jsonWebKeyAndThumbprint
        })
    }
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
            const claims = {
                "htu": localStorage.getItem("token_endpoint"),
                "htm": "POST",
                "jti": generateRandomString(),
                "iat": Math.round(Date.now() / 1000)
            }
        
            const requestParams = {
                grant_type: "authorization_code",
                code: q.code,
                client_id: localStorage.getItem("client_id"),
                redirect_uri: config.redirect_uri,
                code_verifier: localStorage.getItem("pkce_code_verifier")
            }
            // Step 12. Generates a DPoP Client Key Pair
            // https://solidproject.org/TR/oidc-primer#authorization-code-pkce-flow-step-12
        
            // Step 13. Generates a DPoP Header 
            // https://solidproject.org/TR/oidc-primer#authorization-code-pkce-flow-step-13
            await generateDpopHeader(claims)
            .then(async userDPoPHeader => {
                console.log(`userDPoPHeader: ${userDPoPHeader}`);
                localStorage.setItem('user_dpop_header', userDPoPHeader);

                return await fetch(localStorage.getItem("token_endpoint"), {
                    method: 'POST',
                    headers: {
                        'DPoP': userDPoPHeader,
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                        'Authorization': 'Basic ' + btoa(localStorage.getItem("client_id") + ":" + localStorage.getItem("client_secret"))
                    },
                    body: Object.keys(requestParams).map(key => key + '=' + requestParams[key]).join('&')
                })
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
                localStorage.setItem("user_access_token", responseJson.access_token);

                document.getElementById("user_access_token").innerText = responseJson.access_token;
                document.getElementById("sign_in").classList = "hidden";
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
