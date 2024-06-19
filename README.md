**./Web Shell**
================

An advanced PHP based web shell interface for executing system commands and managing files.

**Features**
------------

* Execute system commands and view output in real-time
* Manage files and directories with upload, download, and delete capabilities
* Automatic logout feature for added security(optional)
* Password protection for restricted access(optional)
* Supports several :// connections
* Auto commands for common system administration tasks

  -Includes: Show all groups/users, Show network information, Disable/Restore Firewall, etc.

**Installation**
---------------

1. Run the `passhash.py` script to generate the password hash and configuration values.
```
python passhash.py
```
2. Follow the prompts to enable password authentication, set the login prompt, and set the password.
3. Update the `shell.php` file with the generated configuration values.
```
define('passauth', <value>);
$autolog = <value>;
$passprompt = '<value>';
$passhash = passauth ? '<value>' : '';
```
4. Upload the `shell.php` file to your web server.
5. Access the web shell by navigating to `http://yourdomain.com/shell.php` in your web browser.

**Usage**
---------

1. Enter a command in the "Command" field and click "Execute" to run it.
2. Use the "Fetch" feature to download files from a remote server.
3. Upload files to the server using the "Upload" feature.
4. Manage files and directories using the "CWD" field and the "Upload" and "Delete" buttons.
5. Use the auto commands by selecting them from the dropdown menu.

**Security**
------------

* Password protection is enabled by default. Set `passauth` to `true` and configure the `passhash` variable to enable password protection.
* Automatic logout is enabled by default. Set `autolog` to `true` to enable automatic logout after 15 minutes of inactivity.

**License and Disclaimer**
----------
This web shell is licensed under the MIT License, and is provided as-is and without warranty. Use at your own risk. See the `LICENSE` file for details.
