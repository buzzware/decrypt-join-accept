# decrypt-join-accept

from https://runkit.com/avbentem/deciphering-a-lorawan-otaa-join-accept as referred to by https://lorawan-packet-decoder-0ta6puiniaut.runkit.sh/
modified by Gary McGhee (https://github.com/buzzware)

https://lorawan-packet-decoder-0ta6puiniaut.runkit.sh is a very useful tool, and it you can dump a JoinAccept payload into it, and it will show the RxDelay ad DLSettings, but they are actually nonsense. It turns out that LoRaWAN needs the AppKey to decode the JoinAccept, and it (bizarrely) encodes the packet with the AppKey to decode it.

This tool decodes the Base64 JoinAccept correctly, using the AppKey.

I commented out the MIC check so that the nonce would not be required, but that could be restored as an optional parameter.


Usage :

```
node decrypt-join-accept.js --appkey YOURAPPKEY --payload YOUR_BASE64_JOINACCEPT
```
