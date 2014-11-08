

//apiHnd = { "AppSecret":"app_secret", "Request": {"AppKey": "123", "UserName": "CHRIS", "UserKey":"34", "Nonce": 34 }}
var apiHnd = api.newHandle("/authenticate","123","app_secret", "CHRIS","1234")


var onAuthFailure = function(data) {
	     console.log(data)
		 alert("Auth Failure")
};
var onError = function(data) {
	     console.log(data)
		 alert("Error:"+data.statusText)
};
var onUpdateData = function(data) {
   var $title = $('<h1>').text(data.title);
   var $description = $('<p>').text(data.description);
   $('#info')
             .append($title)
             .append($description);
};


$('#reset-button').click(function() {
	api.resetHandle(apiHnd)
});

$('#fail-error-button').click(function() {
	  console.log(apiHnd);
	  api.read(apiHnd,"/protected/fail_error",onUpdateData,onError,onAuthFailure);
});
$('#fail-auth-button').click(function() {
	  console.log(apiHnd);
	  api.read(apiHnd,"/protected/fail_auth",onUpdateData,onError,onAuthFailure);
});

$('#action-button').click(function() {
	  console.log(apiHnd);
	  api.read(apiHnd,"/protected/data",onUpdateData,onError,onAuthFailure);
});
