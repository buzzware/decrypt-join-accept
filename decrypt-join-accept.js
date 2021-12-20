// from https://runkit.com/avbentem/deciphering-a-lorawan-otaa-join-accept as referred to by https://lorawan-packet-decoder-0ta6puiniaut.runkit.sh/
// modified by Gary McGhee (https://github.com/buzzware)

// Usage :
// node decrypt-join-accept.js --appkey YOURAPPKEY --payload YOUR_BASE64_JOINACCEPT

/*
 * Shows how to decode a LoRaWAN 1.0.x OTAA Join Accept message, and derive the session keys.
 *
 * For a not-encrypted Join Request like 00DC0000D07ED5B3701E6FEDF57CEEAF0085CC587FE913
 * https://github.com/anthonykirby/lora-packet correctly shows:
 *
 *     Message Type = Join Request
 *           AppEUI = 70B3D57ED00000DC
 *           DevEUI = 00AFEE7CF5ED6F1E
 *         DevNonce = CC85
 *              MIC = 587FE913
 *
 * For its response, 204DD85AE608B87FC4889970B7D2042C9E72959B0057AED6094B16003DF12DE145,
 * it currently erroneously suggests:
 *
 *     Message Type = Join Accept
 *         AppNonce = 5AD84D
 *            NetID = B808E6
 *          DevAddr = 9988C47F
 *              MIC = F12DE145
 *
 * However, the Join Accept payload (including its MIC) is encrypted using the secret
 * AppKey (not to be confused with the AppSKey, which is actually derived from the Join
 * Accept). When decrypted using B6B53F4A168A7A88BDF7EA135CE9CFCA, the above Join Accept
 * would yield:
 *
 *     Message Type = Join Accept
 *         AppNonce = E5063A
 *            NetId = 000013
 *          DevAddr = 26012E43
 *       DLSettings = 03
 *          RXDelay = 01
 *           CFList = 184F84E85684B85E84886684586E8400
 *                  = decimal 8671000, 8673000, 8675000, 8677000, 8679000
 *              MIC = 55121DE0
 *
 * (The Things Network has been assigned a 7-bits "device address prefix" a.k.a. NwkID
 * %0010011. Using that, TTN currently sends NetID 0x000013, and a TTN DevAddr always
 * starts with 0x26 or 0x27.)
 *
 * When the DevNonce from the Join Request is known as well, then the session keys can
 * be derived:
 *
 *          NwkSKey = 2C96F7028184BB0BE8AA49275290D4FC
 *          AppSKey = F3A5C8F0232A38C144029C165865802C
 */

var reverse = require('buffer-reverse');
var CryptoJS = require('crypto-js');
var aesCmac = require('node-aes-cmac').aesCmac;

const argv = require('yargs').argv;

// Encrypts the given buffer, returning another buffer.
function encrypt(buffer, key) {
  var ciphertext = CryptoJS.AES.encrypt(
    CryptoJS.lib.WordArray.create(buffer),
    CryptoJS.lib.WordArray.create(key),
    {
      mode: CryptoJS.mode.ECB,
      iv: LORA_IV,
      padding: CryptoJS.pad.NoPadding
    }
  ).ciphertext.toString(CryptoJS.enc.Hex);
  return new Buffer(ciphertext, 'hex');
}


var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Use a lookup table to find the index.
var lookup = new Array(256);
for (var i = 0; i < chars.length; i++) {
  lookup[chars.charCodeAt(i)] = i;
}

function base64decode(base64) {
  var bufferLength = base64.length * 0.75,
    len = base64.length, i, p = 0,
    encoded1, encoded2, encoded3, encoded4;

  if (base64[base64.length - 1] === "=") {
    bufferLength--;
    if (base64[base64.length - 2] === "=") {
      bufferLength--;
    }
  }

  //var arraybuffer = new ArrayBuffer(bufferLength),
  var bytes = new Array(bufferLength);

  for (i = 0; i < len; i+=4) {
    encoded1 = lookup[base64.charCodeAt(i)];
    encoded2 = lookup[base64.charCodeAt(i+1)];
    encoded3 = lookup[base64.charCodeAt(i+2)];
    encoded4 = lookup[base64.charCodeAt(i+3)];

    if (p<bufferLength)
      bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
    if (p<bufferLength)
      bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    if (p<bufferLength)
      bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }

  return bytes;
}




// Secret AppKey as programmed in the device
var appKey = Buffer.from(argv.appkey, 'hex');

// DevNonce as generated in Join Request
//var devNonce = Buffer.from('E263', 'hex');



var payload64 = argv.payload;
var payload = base64decode(payload64);
// Full packet: 0x20 MHDR, Join Accept (12 bytes, 16 bytes optional CFList, 4 bytes MIC)
var phyPayload = Buffer.from(payload, 'hex');

console.log(phyPayload.toString('hex'));

// Initialization vector is always zero
var LORA_IV = CryptoJS.enc.Hex.parse('00000000000000000000000000000000');




// ## Decrypt payload, including MIC
//
// The network server uses an AES decrypt operation in ECB mode to encrypt the join-accept
// message so that the end-device can use an AES encrypt operation to decrypt the message.
// This way an end-device only has to implement AES encrypt but not AES decrypt.
var mhdr = phyPayload.slice(0, 1);
var joinAccept = encrypt(phyPayload.slice(1), appKey);

// ## Decode fields
//
// Size (bytes):     3       3       4         1          1     (16) Optional   4
// Join Accept:  AppNonce  NetID  DevAddr  DLSettings  RxDelay      CFList     MIC
var i = 0;
var appNonce = joinAccept.slice(i, i += 3);
var netID = joinAccept.slice(i, i += 3);
var devAddr = joinAccept.slice(i, i += 4);
var dlSettings = joinAccept.slice(i, i += 1);
var rxDelay = joinAccept.slice(i, i += 1);
if (i + 4 < joinAccept.length) {
  // We need the complete little-endian list (including its RFU byte) for the MIC
  var cfList = joinAccept.slice(i, i += 16);
  // Decode the 5 additional channel frequencies.
  // NOTE: this is for EU868 in LoRaWAN 1.0.x; other regions and versions might need a
  // different decoding, like for US915 in LoRaWAN 1.1 see page 15 of
  // https://lora-alliance.org/sites/default/files/2018-05/lorawan-regional-parameters-v1.1ra.pdf
  var frequencies = [];
  for (var c = 0; c < 5; c++) {
    frequencies.push(cfList.readUIntLE(3 * c, 3));
  }
  var rfu = cfList.slice(15, 15 + 1);
}
var mic = joinAccept.slice(i, i += 4);

// ## Validate MIC
//
// Below, the AppNonce, NetID and all should be added in little-endian format.
// cmac = aes128_cmac(AppKey, MHDR|AppNonce|NetID|DevAddr|DLSettings|RxDelay|CFList)
// MIC = cmac[0..3]

let items = [
  mhdr,
  appNonce,
  netID,
  devAddr,
  dlSettings,
  rxDelay
];

if (cfList)
  items.push(cfList);

var micVerify = aesCmac(
  appKey,
  Buffer.concat(items),
  {returnAsBuffer: true}
).slice(0, 4);

// ## Derive session keys
//
// NwkSKey = aes128_encrypt(AppKey, 0x01|AppNonce|NetID|DevNonce|pad16)
// AppSKey = aes128_encrypt(AppKey, 0x02|AppNonce|NetID|DevNonce|pad16)

// var sKey = Buffer.concat([
//   appNonce,
//   netID,
//   reverse(devNonce),
//   Buffer.from('00000000000000', 'hex')
// ]);
// var nwkSKey = encrypt(Buffer.concat([Buffer.from('01', 'hex'), sKey]), appKey);
// var appSKey = encrypt(Buffer.concat([Buffer.from('02', 'hex'), sKey]), appKey);


class Constants {
  static FCTRL_ADR = 0x80
  static FCTRL_ADRACKREQ = 0x40
  static FCTRL_ACK = 0x20
  static FCTRL_FPENDING = 0x10
  static DLSETTINGS_RXONEDROFFSET_MASK = 0x70
  static DLSETTINGS_RXONEDROFFSET_POS = 4
  static DLSETTINGS_RXTWODATARATE_MASK = 0x0f
  static DLSETTINGS_RXTWODATARATE_POS = 0
  static RXDELAY_DEL_MASK = 0x0f
  static RXDELAY_DEL_POS = 0
}


/**
 * Provide DLSettings.RX1DRoffset as integer
 */
function getDLSettingsRxOneDRoffset(dlSettings) {
  if (dlSettings==null) return null;
  return (
    (dlSettings[0] & Constants.DLSETTINGS_RXONEDROFFSET_MASK) >> Constants.DLSETTINGS_RXONEDROFFSET_POS
  );
}

/**
 * Provide DLSettings.RX2DataRate as integer
 */
function getDLSettingsRxTwoDataRate(dlSettings) {
  if (dlSettings==null) return null;
  return (
    (dlSettings[0] & Constants.DLSETTINGS_RXTWODATARATE_MASK) >> Constants.DLSETTINGS_RXTWODATARATE_POS
  );
}

/**
 * Provide RxDelay.Del as integer
 */
function getRxDelayDel(rxDelay) {
  if (rxDelay==null) return null;
  return (rxDelay[0] & Constants.RXDELAY_DEL_MASK) >> Constants.RXDELAY_DEL_POS;
}


var r = '     Payload = ' + phyPayload.toString('hex')
  + '\n        MHDR = ' + mhdr.toString('hex')
  + '\n Join Accept = ' + joinAccept.toString('hex')
  + '\n    AppNonce = ' + (reverse(appNonce)).toString('hex')
  + '\n       NetID = ' + (reverse(netID)).toString('hex')
  + '\n     DevAddr = ' + (reverse(devAddr)).toString('hex')
  + '\n  DLSettings = ' + dlSettings.toString('hex')
  + '\n  DLSettings.RX1DRoffset = ' + String(getDLSettingsRxOneDRoffset(dlSettings))
  + '\n  DLSettings.RX2DataRate = ' + String(getDLSettingsRxTwoDataRate(dlSettings))
  + '\n     RXDelay = ' + String(getRxDelayDel(rxDelay))
  + '\n message MIC = ' + mic.toString('hex')
 + '\nverified MIC = ' + micVerify.toString('hex')
// + '\n     NwkSKey = ' + nwkSKey.toString('hex')
// + '\n     AppSKey = ' + appSKey.toString('hex')
  ;

if (cfList) {
  r += '\n      CFList = ' + String(cfList && cfList.toString('hex'))
    + '\n             = decimal ' + frequencies.join(', ') + '; RFU ' + rfu.toString('hex');
}

console.log(r);

//'<pre>\n' + r + '\n</pre>';
