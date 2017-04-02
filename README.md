[![Build Status](https://travis-ci.org/righettod/ws-probing-shell.svg?branch=master)](https://travis-ci.org/righettod/ws-probing-shell)
[![Requirements Status](https://requires.io/github/righettod/ws-probing-shell/requirements.svg?branch=master)](https://requires.io/github/righettod/ws-probing-shell/requirements/?branch=master)
[![Dependency Status](https://www.versioneye.com/user/projects/58d7820fdcaf9e0045d97311/badge.svg?style=flat-square)](https://www.versioneye.com/user/projects/58d7820fdcaf9e0045d97311)

# WS Probing Shell

Interactive shell in order to probe/analyze a WebSocket endpoint.

The project is under developmement and the creation of a pip module is planned in order to facilitate the installation/update.

# Motivation

This shell was developed because I didn't find a tool or a extension in Burp/OWASP Zap allowing me to deeply inspect and probe a WebSocket endpoint in the same way that I can do it for example for a web endpoint like a REST web service.

# Python version requirement 

Python >= 3.5

# Dependencies

Use the following command to install the dependencies packages:

```
pip install -r requirements.txt
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
analyze     help                                 quit
connect     probe_connection_channels_supported  replay
disconnect  probe_request_connection_limit       search
fuzz        probe_request_length_limit           show

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

# Commands flow

Use of the shell is always something like this:

1. **connect** command using the targeted endpoint (`WS://xxx` or `WSS://xxx`) identified for example with Burp or ZAP.
2. _Action_ command (1 or N times) like: 
    * **replay**,
    * **fuzz**,
    * **probe_request_connection_limit**,
    * **probe_request_length_limit**,
    * **probe_connection_channels_supported**,
    * ...
3. _Analysis_ command (1 or N times) like: 
    * **analyze**,
    * **search**,
    * **show**,
    * ...
3. Finalization command like:
    * **disconnect** command if you want to target another endpoint,
    * **quit** command if you want to exit the shell.
