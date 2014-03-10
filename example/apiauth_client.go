package main

import (
	"encoding/json"
	"fmt"
	_ "github.com/codegangsta/martini"
	"github.com/pagecr/apiauth"
	"io/ioutil"
	"net/http"
	"strings"
)

func main() {
	baseURL := "http://127.0.0.1:3000"

	// hit public area
	resp, err := http.Get(baseURL)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(body))

	// authenticate -- get a token for this app/user combo
	tr := apiauth.TokenRequest{}
	tr.AppKey = "123"
	tr.Username = "CHRIS"
	tr.UserKey = "34"
	tr.Nonce = "34"
	tr.Sign()
	jtr, err := json.Marshal(tr)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp, err = http.Post(baseURL+"/authenticate", "application/json", strings.NewReader(string(jtr)))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	tok := apiauth.TokenResponse{}
	if err := json.Unmarshal(body, &tok); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("server replied:%+v\n", tok)

	// hit protected area
	client := &http.Client{}
	var req *http.Request
	req, err = http.NewRequest("GET", baseURL+"/protected", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	//        sig := tok.ComputeSignature(req, "app_secret")
	appSecret := "app_secret"
	req.Header.Add("Authorization", tok.AuthHeaderString(appSecret))
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(body))

}
