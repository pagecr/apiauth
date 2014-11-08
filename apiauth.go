package apiauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/auth"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

/*
*  How it works:
* - client / server share an appKey, which is associated with an appSecret
* - client obtains username and key for the app using out of band methods
* - client requests a token using appkey, username, and userkey, all signed with app secret
* - if authenticated, server returns an authType, token, and secret that can be used in API requests
* - API requests add an authorization header that contains token info signed with the secret
/*
var siteSig string
var secret string

var token string
func Token(tokenRequest *tokenRequest) (token string,err error) {
	token = "ABC123"
        return
}
*/

/*
* Every App has a secret key associated with
* it that is shared between the app, and its clients
* The key be be periodically regenerated, but is hard coded here
* and is not app specific.
 */
func getAppSecret(appKey string) string {
	return "app_secret"
}
func getUserSecret(userKey string) string {
	return "1234"
}

/*
* Routine that validates access to the App
 */
func authorizedAppUser(appKey string, userKey string) bool {
	return true
}

/*
*  Need facility to associate token string with toke info
*  This simple way only works for a single server
*  so needs to be replaced
 */
var savedTokenData *TokenInfo

func saveTokenData(token string, tr *TokenInfo) {
	savedTokenData = tr
}
func getTokenData(token string) *TokenInfo {
	return savedTokenData
}

/*
* Token management
 */
type TokenRequest struct {
	AppKey string // well-known key embedded in the application

	UserKey  string // Username and userKey are supplied by client via user entry
	UserHash string

	Nonce     int64 // likey the unix time; variable to help prevent signature duplication (throwat replay attacks)
	Signature string
}

type TokenInfo struct {
	Request  *TokenRequest
	Response *TokenResponse
	Nonce    int64
}

func (tr TokenRequest) ComputeSignature() string {
	msg := fmt.Sprintf("%s%s%s%d", tr.AppKey, tr.UserKey, tr.UserHash, tr.Nonce)
	sig := ComputeHmacSHA1(msg, getAppSecret(tr.AppKey))
	log.Println("Computing Signature for:", msg)
	log.Println("Signature:", sig)
	return sig
}
func (tr TokenRequest) ComputeUserHash() string {
	msg := fmt.Sprintf("%s", tr.UserKey)
	secret := fmt.Sprintf("%s%d", getUserSecret(tr.UserKey), tr.Nonce)
	uh := ComputeHmacSHA1(msg, secret)
	log.Println("Computing hash for:", msg)
	log.Println("with secret:", secret)
	log.Println("Signature:", uh)
	return uh
}
func (tr *TokenRequest) Sign() {
	tr.Signature = tr.ComputeSignature()
}

type TokenResponse struct {
	AuthType string
	Token    string
}

/*
* Just an identifier -- nothing special about it.
 */
var DefaultAuthType string = "MCAA"

/*
* Signature and method used to authenticate a user
* which is usually a callback to user code
 */
type AppAuthHandler func(appKey string, userKey string) bool

var appAuthHandler AppAuthHandler = authorizedAppUser

func SetAppAuthHandler(newHandler AppAuthHandler) {
	appAuthHandler = newHandler
}

func CreateNewToken(tr *TokenRequest) (token string, err error) {
	sig := tr.Signature           // signature passed in
	csig := tr.ComputeSignature() // computed signature based on what was passed
	log.Println("supplied signature:", sig)
	log.Println("computed signature:", csig)
	if !auth.SecureCompare(csig, sig) {
		// provided signature doesn't match what was computed
		log.Printf("client supplied:%+v\n", tr)
		err = errors.New("Invalid Token Request Signature")
		return
	}
	chash := tr.ComputeUserHash()
	hash := tr.UserHash
	if !auth.SecureCompare(chash, hash) {
		// provided userhash doesn't match what was computed
		log.Printf("client supplied:%+v\n", tr)
		err = errors.New("Invalid Token Request User Hash")
		return
	}
	if !appAuthHandler(tr.AppKey, tr.UserKey) {
		// provided userhash doesn't match what was computed
		log.Printf("client supplied:%+v\n", tr)
		err = errors.New("User has not authorized this App")
		return
	}
	token = genRandomToken()
	return
}

func (tr TokenResponse) ComputeSignature(secret string, nonce string) string {
	msg := fmt.Sprintf("%s %s;%s", tr.AuthType, tr.Token, nonce)
	computedSig := ComputeHmacSHA1(msg, secret)
	return computedSig
}

func (tr TokenResponse) AuthHeaderString(secret string, nonce string) string {
	ahs := fmt.Sprintf("%s %s;%s:%s", tr.AuthType, tr.Token, nonce, tr.ComputeSignature(secret, nonce))
	return ahs
}

/*
* Before access is granted to protected areas, the person
* must call a method that invokes the 'Authenticate' method
* which will generate and return a token to the requester
* provided that authenticate and are granted access.
 */
func Authenticate() martini.Handler {
	var warned bool

	//secret = "hello"

	//siteAuth = base64.StdEncoding.EncodeToString([]byte(token + ":"))
	// curl -X POST -d '{ "AppKey":"123","UserIdKey":"34","Nonce":"34"}' http://localhost:3000/authenticate
	return func(req *http.Request, res http.ResponseWriter, log *log.Logger) {
		if !warned && strings.HasPrefix(req.Proto, "HTTP/") {
			log.Println("Warning: Transport is insecure.  Use only HTTPS if security is a concern.")
			warned = true
		}

		log.Printf("Create token request")
		tokenRequest := TokenRequest{}
		log.Printf("Read data")
		data, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Println(err)
			http.Error(res, "Read of Token Request Failed - did you send data?", 401)
			return
		}
		defer req.Body.Close()
		log.Printf("Unmarshal data:", data)
		if err := json.Unmarshal(data, &tokenRequest); err != nil {
			log.Println(err)
			http.Error(res, "Invalid Token Request; json invalid", 401)
			return
		}
		log.Printf("client supplied:%+v\n", tokenRequest)

		log.Printf("Create a new token")
		var token string
		if token, err = CreateNewToken(&tokenRequest); err != nil {
			log.Println(err)
			http.Error(res, "Invalid Token Request; key combination not valid", 401)
			return
		}

		log.Printf("Set header")
		//siteSig = ComputeHmacSHA1(token+":", secret)
		res.Header().Set("Content-Type", "application/json")
		//tokenResponse := &TokenResponse{"MCSS", token, siteSig}

		log.Printf("Create token reponse")
		tokenResponse := TokenResponse{DefaultAuthType, token}
		log.Printf("Save token response for later")
		saveTokenData(token, &TokenInfo{Nonce: tokenRequest.Nonce, Request: &tokenRequest, Response: &tokenResponse})
		log.Printf("Marshal token response")
		jr, err := json.Marshal(tokenResponse)
		if err != nil {
			log.Println(err)
			http.Error(res, "Generated Invalid Token Response; something odd going on here", 401)
			return
		}
		log.Println(jr)
		fmt.Println(jr)
		log.Printf("Send token in returned data stream")
		fmt.Fprintf(res, "%s", jr)
		return

		//return "MCAA\n" + token + ":\n" + siteSig + "\n"
	}
}

/*
* martini middleware to make sure requests are authorized.
* These are middleware calls that identify whether or not
* access is retricted.
 */

func NotRequired() martini.Handler {
	return NotAuthRequired
}
func Required() martini.Handler {
	return AuthRequired
}
func NotAuthRequired(res http.ResponseWriter, req *http.Request) {}
func AuthDenied(res http.ResponseWriter, req *http.Request) {
	http.Error(res, "Not Authorized", http.StatusUnauthorized)
	return
}
func AuthRequired(res http.ResponseWriter, req *http.Request) {
	fmt.Println("AUTH REQUIRED")
	authHdr := req.Header.Get("Authorization")
	fmt.Println("Ahdr:", authHdr)

	patt := regexp.MustCompile(`(\S+) (\S+);(\d+):(\S+)`)
	m := patt.FindSubmatch([]byte(authHdr))
	if len(m) == 0 {
		http.Error(res, "Not Authorized - Invalid Authorization Header", http.StatusUnauthorized)
		return
	}

	authType := string(m[1])
	token := string(m[2])
	nonce := atoi(string(m[3]))
	sig := string(m[4])
	fmt.Println("T:", authType, "t:", token, "n:", nonce, "s:", sig)

	fmt.Println("token=", token)
	lastToken := getTokenData(token)
	if lastToken == nil || authType != lastToken.Response.AuthType {
		http.Error(res, "Not Authorized - Invalid Token or AuthType", http.StatusUnauthorized)
		return
	}
	if nonce <= lastToken.Nonce {
		http.Error(res, "Not Authorized - Invalid Nonce", http.StatusUnauthorized)
		return
	}

	secret := getAppSecret(lastToken.Request.AppKey)
	cHdr := lastToken.Response.AuthHeaderString(secret, fmt.Sprintf("%d", nonce))
	//computedSig := ComputeHmacSHA1(msg, secret)
	if !auth.SecureCompare(authHdr, cHdr) {
		http.Error(res, "Not Authorized - Invalid Header/Sig", http.StatusUnauthorized)
		return
	}

	lastToken.Nonce = nonce
	saveTokenData(token, lastToken)
}

/*
* Utilities
 */

/*
* when we generate a new token, we want it to be a random
* and unique string.  This is a hack for now.
 */
func genRandomToken() string {
	return "rtoken"
}
func atoi(s string) int64 {
	i, err := strconv.ParseInt(s, 10, 0)
	if err != nil {
		i = 0
	}
	return i
}

func ComputeHmacSHA1(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
