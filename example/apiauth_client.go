package main

import (
	"encoding/json"
	"fmt"
	_ "github.com/go-martini/martini"
	"github.com/go-shaken/apiauth"
	"io/ioutil"
	"net/http"
	"strings"
)

func main() {
	baseURL := "http://127.0.0.1:3000"
	appSecret := "app_secret"

	// hit public area
	//
	//
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
	//
	//
	tr := apiauth.TokenRequest{}
	tr.AppKey = "123"
	tr.Username = "CHRIS"
	tr.UserKey = "34"
	tr.Nonce = 34
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
	fmt.Printf("server replied with a token that we'll use:%+v\n", tok)

	// Get a client and request structure
	client := &http.Client{}
	var req *http.Request

	// hit protected area
	//
	//
	req, err = http.NewRequest("GET", baseURL+"/protected", nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	tr.Nonce += 1
	req.Header.Add("Authorization", tok.AuthHeaderString(appSecret, fmt.Sprintf("%d", tr.Nonce)))
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

	// hit protected area a second time
	//
	//

	// update header
	tr.Nonce += 1
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", tok.AuthHeaderString(appSecret, fmt.Sprintf("%d", tr.Nonce)))
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

	// hit protected area a third time -- but fail to increment nonce
	//
	//

	// reuse header, aka replay attack
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

	// hit protected area a final time
	//
	//

	// update header
	tr.Nonce += 1
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", tok.AuthHeaderString(appSecret, fmt.Sprintf("%d", tr.Nonce)))
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

	// hit protected area for data
	//
	//

	req, err = http.NewRequest("GET", baseURL+"/protected/data", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	tr.Nonce += 1
	req.Header.Add("Authorization", tok.AuthHeaderString(appSecret, fmt.Sprintf("%d", tr.Nonce)))
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
