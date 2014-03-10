package apiauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/codegangsta/martini"
	"github.com/martini-contrib/auth"
	_ "github.com/martini-contrib/render"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type TokenRequest struct {
	AppKey    string
	Username  string
	UserKey   string
	Nonce     string
	Signature string
}

func (tr TokenRequest) ComputeSignature() string {
	msg := tr.AppKey + tr.Username + tr.UserKey + tr.Nonce
	sig := ComputeHmacSHA1(msg, getAppSecret(tr.AppKey))
	log.Println("Computing Signature for:", msg)
	log.Println("Signature:", sig)
	return sig
}
func (tr *TokenRequest) Sign() {
	tr.Signature = tr.ComputeSignature()
}

type TokenResponse struct {
	AuthType string
	Token    string
}

/*
var siteSig string
var secret string

var token string
func Token(tokenRequest *tokenRequest) (token string,err error) {
	token = "ABC123"
        return
}
*/

func genRandomToken() string {
	return "rtoken"
}
func getAppSecret(appKey string) string {
	return "app_secret"
}
func authorizedAppUser(appKey string, username string, userKey string) bool {
	return true
}

var savedTokenData *TokenRequest

func saveTokenData(token string, tr *TokenRequest) {
	savedTokenData = tr
}

func getTokenData(token string) *TokenRequest {
	return savedTokenData
}

func CreateNewToken(tr *TokenRequest) (token string, err error) {
	csig := tr.ComputeSignature()
	sig := tr.Signature
	log.Println("supplied signature:", sig)
	log.Println("computed signature:", csig)
	if !auth.SecureCompare(csig, sig) {
		err = errors.New("Invalid Token Request Signature")
		return
	}
	if !authorizedAppUser(tr.AppKey, tr.Username, tr.UserKey) {
		err = errors.New("User has not authorized this App")
		return
	}
	token = genRandomToken()
	saveTokenData(token, tr)
	return
}

func (tr TokenResponse) ComputeSignature(secret string) string {
	msg := tr.AuthType + " " + tr.Token
	computedSig := ComputeHmacSHA1(msg, secret)
	return computedSig
}
func (tr TokenResponse) AuthHeaderString(secret string) string {
	ahs := tr.AuthType + " " + tr.Token + ":" + tr.ComputeSignature(secret)
	return ahs
}
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

		tokenRequest := TokenRequest{}
		data, _ := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err := json.Unmarshal(data, &tokenRequest); err != nil {
			log.Println(err)
			http.Error(res, "Invalid Token Request; json invalid", 401)
			return
		}
		log.Printf("client supplied:%+v\n", tokenRequest)

		var err error
		var token string
		if token, err = CreateNewToken(&tokenRequest); err != nil {
			log.Println(err)
			http.Error(res, "Invalid Token Request; key combination not valid", 401)
			return
		}

		//siteSig = ComputeHmacSHA1(token+":", secret)
		res.Header().Set("Content-Type", "application/json")
		//tokenResponse := &TokenResponse{"MCSS", token, siteSig}

		tokenResponse := &TokenResponse{"MCAA", token}
		jr, _ := json.Marshal(tokenResponse)
		fmt.Fprintf(res, "%s", jr)
		return

		//return "MCAA\n" + token + ":\n" + siteSig + "\n"
	}
}

func AuthRequired(res http.ResponseWriter, req *http.Request) {
	authHdr := req.Header.Get("Authorization")
	parts := strings.Split(authHdr, ":")
	p2 := strings.Split(parts[0], " ")
	token := p2[1]
	log.Println("token=", token)
	/*
		if parts[0] != "MCAA "+token {
			http.Error(res, "Not Authorized - Invalid Token", http.StatusUnauthorized)
			return
		}
	*/

	msg := parts[0]
	tr := getTokenData(token)
	computedSig := ComputeHmacSHA1(msg, getAppSecret(tr.AppKey))
	if !auth.SecureCompare(parts[1], computedSig) {
		http.Error(res, "Not Authorized - Invalid Sig", http.StatusUnauthorized)
		return
	}
}

func ComputeHmacSHA1(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
