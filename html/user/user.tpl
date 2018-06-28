<html><head><title>User Credentials</title>
<link rel="stylesheet" type="text/css" href="style.css">

</head>
<body>
<div id="main">
    <p>
        Current WiFi mode: %WiFiMode%
    </p>
    <form name="userform" action="setuser.cgi" method="post">
    <p>
        Please enter new user name and password.<br>

        <input type="text" name="user" val="%user%"> <br />
        <input type="text" name="pass" val="%pass%"> <br />
        <input type="submit" name="connect" value="Update">
    </p>
</div>
</body>
</html>
