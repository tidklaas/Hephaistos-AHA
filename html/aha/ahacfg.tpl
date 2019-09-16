<html><head><title>AHA Configuration</title>
<link rel="stylesheet" type="text/css" href="style.css">

</head>
<body>
<div id="main">
    <form name="userform" action="ahasetcfg.cgi" method="post">
    <p>
        Please enter new user name and password.<br>

        <table>
        <tr>
        <td>F!Box User</td>
        <td><input type="text" name="fbox_user" value="%fbox_user%"></td>
        </tr>

        <tr>
        <td>F!Box Pass</td>
        <td><input type="text" name="fbox_pass" value="%fbox_pass%"></td>
        </tr>

        <tr>
        <td>F!Box Addr</td>
        <td><input type="text" name="fbox_addr" value="%fbox_addr%"></td>
        </tr>

        <tr>
        <td>F!Box Port</td>
        <td><input type="text" name="fbox_port" value="%fbox_port%"></td>
        </tr>
        </table>

        <input type="submit" name="connect" value="Update">
    </p>
</div>
</body>
</html>
