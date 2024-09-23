package main

import (
    "crypto/rand"		//for generating random numbers (used in RSA key generation)
    "crypto/rsa"		//for working with RSA keys
    "encoding/base64"	//for encoding keys in base64 format
    "encoding/json"		//for encoding and decoding JSON data
    "log"				//for logging messages to the console
    "math/big"			//for working with big integers (used in RSA)
    "net/http"			//for setting up the HTTP server and handling requests
    "sync"				
    "time"				//for working with time and setting expirations

    "github.com/golang-jwt/jwt/v4"	//JWT library for signing and verifying tokens
    "github.com/google/uuid"		//for generating unique Key IDs (kid)
)

//constants for RSA key generation and expiry
const (
    rsaKeySize    = 2048				//RSA key size
    keyExpiryTime = 10 * time.Minute 	//key valid duration
    jwtExpiry     = 5 * time.Minute  	//JWT valid duration
)

//JSON Web Key, standardized format for public keys
type JWK struct {
    KID string `json:"kid"`	//Key ID (kid)
    N   string `json:"n"`	//modulus
    E   string `json:"e"`	//exponent
    Alg string `json:"alg"`	//algorithm
    Kty string `json:"kty"`	//key type (RSA)
    Use string `json:"use"`	//key usage
}

//web Key Set
type JWKS struct {
    Keys []JWK `json:"keys"`
}

//RSA key pair with metadata
type Key struct {
    PrivateKey  *rsa.PrivateKey	//private key used for signing JWTs
    PublicKey   *rsa.PublicKey	//public key used for verification
    CreationTime time.Time		//key creation time
}

//global variables to store keys and manage concurrency
var (
    keys      = make(map[string]*Key) //map of kid to Key
    keysMutex sync.RWMutex
)

func main() {
    //generate initial RSA key pair
    err := generateAndStoreKey()
	//check if error occured and output statement
    if err != nil {
        log.Fatalf("Failed to generate initial key: %v", err)
    }

    //background process to periodically remove expired keys
    go keyExpiryHandler()

    //set up HTTP handlers
    http.HandleFunc("/.well-known/jwks.json", jwksHandler)	//serves public keys
    http.HandleFunc("/auth", authHandler)					//issues JWT tokens

    //start server
    log.Println("JWKS server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

//generateAndStoreKey generates a new RSA key pair, assigns a unique kid, and stores it
func generateAndStoreKey() error {
    privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
    if err != nil {
        return err
    }

    kid := uuid.New().String()	//generate unique Key ID (kid)

	//store key in global map with current time
    keysMutex.Lock()
    keys[kid] = &Key{
        PrivateKey:  privateKey,
        PublicKey:   &privateKey.PublicKey,
        CreationTime: time.Now(),
    }
    keysMutex.Unlock()

    log.Printf("Generated new key with kid: %s\n", kid)	//log key creation
    return nil
}

// keyExpiryHandler periodically checks for expired keys and removes them
func keyExpiryHandler() {
    ticker := time.NewTicker(1 * time.Minute)	//run every minute
    defer ticker.Stop()

    for {
        <-ticker.C
        now := time.Now()

        keysMutex.Lock()
		//iterate over keys and remove any that have expired
        for kid, key := range keys {
            if now.Sub(key.CreationTime) > keyExpiryTime {
                delete(keys, kid)
                log.Printf("Expired key removed: %s\n", kid)	//log removal
            }
        }
        keysMutex.Unlock()

        //generate a new key when one expires
        keysMutex.RLock()
        if len(keys) == 0 {
            keysMutex.RUnlock()
            log.Println("No active keys found. Generating a new key.")
            if err := generateAndStoreKey(); err != nil {
                log.Printf("Error generating new key: %v\n", err)
            }
        } else {
            keysMutex.RUnlock()
        }
    }
}

//wksHandler serves the JWKS endpoint by returning all unexpired public keys
func jwksHandler(w http.ResponseWriter, r *http.Request) {
    //check if request method is GET, only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	keysMutex.RLock()
    defer keysMutex.RUnlock()

    var jwks JWKS

	//convert each key to JWK format and add it to the JWKS
    for kid, key := range keys {
        jwk, err := convertToJWK(kid, key.PublicKey)
        if err != nil {
            log.Printf("Error converting key to JWK: %v\n", err)
            continue
        }
        jwks.Keys = append(jwks.Keys, jwk)
    }

	//return the JWKS as a JSON response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jwks)
}

//convertToJWK converts an RSA public key to a JWK
func convertToJWK(kid string, pubKey *rsa.PublicKey) (JWK, error) {
    nBytes := pubKey.N.Bytes()	//get modulus
    eBytes := big.NewInt(int64(pubKey.E)).Bytes()	//get exponent

	//return a JWK object with the base64 values
    return JWK{
        KID: kid,
        N:   base64.RawURLEncoding.EncodeToString(nBytes),
        E:   base64.RawURLEncoding.EncodeToString(eBytes),
        Alg: "RS256",
        Kty: "RSA",
        Use: "sig",
    }, nil
}

//authHandler issues JWTs. If the "expired" query parameter is set, it uses an expired key.
func authHandler(w http.ResponseWriter, r *http.Request) {
    //only allow POST requests
    if r.Method != http.MethodPost {
        http.Error(w, "405 Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    //check if the client is requesting an expired JWT
    expired := false
    if val := r.URL.Query().Get("expired"); val == "true" {
        expired = true
    }

    var keyToUse *Key
    var kid string

    keysMutex.RLock()
    for k, v := range keys {
        kid = k
        keyToUse = v
        break // Use the first available key
    }
    keysMutex.RUnlock()

    if keyToUse == nil {
        http.Error(w, "No available keys to sign token", http.StatusInternalServerError)
        return
    }

	//create a new JWT with the standard claims
    token := jwt.New(jwt.SigningMethodRS256)

    claims := token.Claims.(jwt.MapClaims)
    claims["iss"] = "jwks-server"
    claims["sub"] = "user123"
    claims["iat"] = time.Now().Unix()
	
	//set the token expiration, either in the past (for expired) or in the future
    if expired {
        claims["exp"] = time.Now().Add(-1 * time.Hour).Unix() //set expiry in past
    } else {
        claims["exp"] = time.Now().Add(jwtExpiry).Unix()	//valid for 5 min
    }

    token.Header["kid"] = kid	//include the key ID (kid) in the JWT header

	//sign the token using the private key
    tokenString, err := token.SignedString(keyToUse.PrivateKey)
    if err != nil {
        http.Error(w, "Failed to sign token", http.StatusInternalServerError)
        return
    }

	//return the signed JWT as a JSON response
    response := map[string]string{
        "token": tokenString,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
