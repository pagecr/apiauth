
var api = {

STATUS_AUTH_NEEDED : "auth needed",
STATUS_AUTH_PENDING : "auth pending",
STATUS_AUTH_FAILED : "auth failed",
STATUS_AUTHORIZED : "authorized",

newHandle: function(authURL, appKey, appSecret, userKey, userSecret) {
	var nonce = (new Date).getTime();
	var uh = api._hash(userKey,userSecret+nonce)
	hnd = { "AuthURL":authURL, 
		"Status": api.STATUS_AUTH_NEEDED,
		"Request": { 
			"AppKey": appKey, 
			"AppSecret": appSecret, 
			"UserKey": userKey, 
			"UserHash": uh, 
			"Nonce": nonce,
		},
		"Response": null,
		"Header": { "Nonce": null },
	}
	return hnd
},

resetHandle: function(pHnd) {
	if (pHnd != null) {
       pHnd.Status = api.STATUS_AUTH_NEEDED;
	   pHnd.Response= null;
	   pHnd.Header.Nonce= (new Date).getTime();
	}
},

authenticate: function(pHnd,pAuthErr) {
	console.log("authenticating")
	if (pHnd == null) {
	    console.log("pHnd is null")
		return;
	}
	pHnd.Status = api.STATUS_AUTH_PENDING;
	api._newTokenRequest(pHnd);
	js = JSON.stringify(pHnd.Request);
	console.log(js);
	$.ajax({
	   url: pHnd.AuthURL,
	   async: false,
	   data: js,
	   error: function() { pHnd.Status = api.STATUS_AUTH_FAILED; pAuthErr(); },
       success: function(d) { 
	     pHnd.Status = api.STATUS_AUTHORIZED
		 pHnd.Response = d; 
		 pHnd.Header = { "Nonce":pHnd.Request.Nonce }; 
		 console.log(d); 
   	   },
	   dataType: 'json',
	   type: 'POST'
	});
	return pHnd;
},

_hash: function(msg,secret) {
	var hash = CryptoJS.HmacSHA1(msg, secret);
	var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);
	return hashInBase64;
},

_newTokenRequest: function(pHnd) {
	if (pHnd == null) {
		return;
	}
	//console.log(pHnd);
	var msg = pHnd.Request.AppKey + pHnd.Request.UserKey + pHnd.Request.UserHash + pHnd.Request.Nonce;
	console.log(msg);
	pHnd.Request.Signature = api._hash(msg,pHnd.Request.AppSecret);
	console.log("WithSig:"+JSON.stringify(pHnd.Request));
},

signAuthHeader: function(pHnd) {
	if (pHnd == null) {
		return null;
	}
	var msg = pHnd.Response.AuthType + " "+pHnd.Response.Token + ";"+ pHnd.Header.Nonce;
	//console.log(msg);
	//console.log(pHnd);
	pHnd.Header.Msg = msg;
	pHnd.Header.Signature = api._hash(msg,pHnd.Request.AppSecret);
	pHnd.Header.Body = msg + ":" + pHnd.Header.Signature;
	console.log("Header:"+JSON.stringify(pHnd.Header));
	return pHnd
},

read: function(pHnd,pURL,pSuccess,pErr,pAuth) {
      var headers= { };
	  if (pHnd != null) {
		   if (pHnd.Status == api.STATUS_AUTH_NEEDED ) {
			   pHnd = api.authenticate(pHnd,pAuth);
		   }
		   if (pHnd.Status != api.STATUS_AUTHORIZED) {
			       console.log("Ignoring request because:",pHnd.Status)
				   return
		   }
	       pHnd.Header.Nonce = (new Date).getTime();
	       pHnd = api.signAuthHeader(pHnd);
	       console.log(pHnd);
		   headers= { 'Authorization': pHnd.Header.Body }
	   }
	   $.ajax({
	         url: pURL,
		     headers: headers,
//	         data: { format: 'json' },
	         error: function(d) { if (d == null || d.status != 401) {  pErr(d); } else { pAuth(d) } },
		     success: function(d) { pSuccess(d); },
	         dataType: 'json',
	         type: 'GET'
		     });
},
};
