# Phishing-detection-application-using-VirusTotal-and-GPT
The following project is an application that utilizes Virustotal and chatGPT API to  create a new generation phising scanning app that will collect the data of possible attack in 2 json file one for suspicious attack and another for conformed attack. 
The use of virustotal api is self explanotory however, using Gpt Api is new as it actually analyse the whole url according to given prompt and have added functon to make exception and update the whole process without changing the code and only using prompting function. 
The json file are use to collect evedence like ip of attack server, email of attacker and time and date of attck so that it can be documented  easily.
the blacklist.js file are conformed attak used by scanner and sus.js are suspicious file detectd by gpt making it be veried by actual human expert so the chances of phising can be very low. 
the following application utilizes 3 core technology for detecting phing application; AI detction using GPT (although it shoud be called AI chat application) and signature detection and sandboxing function utilising Virustotal api. thus app makes use all the possable technology to scan the phishing attack.


requirement: api key of virustotal and chatGPT (ps: make sure its premium verson or else it is a lot of hassle.)

future enhancement goal: to make it automatilly block server in blacklist.js on comapanys edge router  however it will require to use perticular server and sometime the company might need to use the following server due to varios curcemstances so im confuse in this point.
another goal is to make this a browsers extention to enance it funcanality. 