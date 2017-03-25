# Description

Interactive shell in order to probe/analyze a WebSocket endpoint.

The project is under developmement and the creation of a pip module is planned in order to facilitate the installation/update.

# Motivation

This shell was developed because I didn't find a tool or a extension in Burp/OWASP Zap allowing me to deeply inspect and probe a WebSocket endpoint in the same way that I can do it for a web endpoint like a REST web service for example.

# Python version requirement 

Python >= 3.5

# Dependencies

```
pip install websocket-client colorama termcolor tabulate
```

# How to use it?

Run the script:

 ```
python ws_probing_shell.py
 ```
 
Type the following command to obtains the list of available commands and help about them:

```
.:Welcome to the WebSocket probing shell:.

Type help or ? to list commands.

(Cmd) help

Documented commands (type help <topic>):
========================================
analyze     fuzz                            probe_request_length_limit  search
connect     help                            quit
disconnect  probe_request_connection_limit  replay

(Cmd) help replay

        Replay a specified message a specified number of times

        Syntax:
        replay -m [path_to_message_file] -n [repetition_count]

        Example:
        replay -m /tmp/message.txt -n 20

        Parameters:
        path_to_message_file: Path to the file (text format) containing the message to replay, 
                              no space in path.
        repetition_count: Number of time that the message must be send

(Cmd)
```

Commands flow is always something like:
1. **connect** command using the endpoint URL identified with Burp or ZAP for example
2. Action commands like: **replay**/**fuzz**/...
3. Analysis command like: **analyze**/**search**/**probe_request_connection_limit**/**probe_request_length_limit**/...
3. **disconnect** command if you want to target another endpoint or **quit** command if you want to exit the shell
