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

        <table>
        <tr>
        <td>User</td>
        <td><input type="text" name="user" value="%user%"></td>
        </tr>

        <tr>
        <td>Pass</td>
        <td><input type="text" name="pass" value="%pass%"></td>
        </tr>
        </table>

        <input type="submit" name="connect" value="Update">
    </p>
</div>
</body>
</html>
