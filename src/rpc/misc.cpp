// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2014-2019 The DigiByte Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <key_io.h>
#include <validation.h>
#include <httpserver.h>
#include <net.h>
#include <netbase.h>
#include <outputtype.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <timedata.h>
#include <util.h>
#include <utilstrencodings.h>
#include <warnings.h>
#include <base58.h>
#include "txmempool.h"

#include <stdint.h>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <univalue.h>


bool getAddressFromIndex(const int &type, const uint160 &hash, std::string &address)
 {

     if (type == 2) {
         address = EncodeDestination(CScriptID(hash));
     } else if (type == 1) {
         address =  EncodeDestination(CKeyID(hash));
     } else {
         return false;
     }
     return true;
 }

bool getAddressesFromParams(const UniValue& params, std::vector<std::pair<uint160, int> > &addresses)
 {
     if (params[0].isStr()) {
         uint160 hashBytes;
         int type = 0;
         if (!DecodeIndexKey(params[0].get_str(), hashBytes, type)) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
         }
         addresses.push_back(std::make_pair(hashBytes, type));
     } else if (params[0].isObject()) {

         UniValue addressValues = find_value(params[0].get_obj(), "addresses");
         if (!addressValues.isArray()) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
         }

         std::vector<UniValue> values = addressValues.getValues();

         for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {

             uint160 hashBytes;
             int type = 0;
             if (!DecodeIndexKey(it->get_str(), hashBytes, type)) {
                 throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
             }
             addresses.push_back(std::make_pair(hashBytes, type));
         }
     } else {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
     }

     return true;
 }


bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                 std::pair<CAddressUnspentKey, CAddressUnspentValue> b) {
     return a.second.blockHeight < b.second.blockHeight;
 }



bool timestampSort(std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> a,
                    std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> b) {
     return a.second.time < b.second.time;
 }

 UniValue getaddressmempool(const JSONRPCRequest& request)
 {
     if (request.fHelp || request.params.size() != 1)
         throw std::runtime_error(
             "getaddressmempool\n"
             "\nReturns all mempool deltas for an address (requires addressindex to be enabled).\n"
             );

     std::vector<std::pair<uint160, int> > addresses;

     if (!getAddressesFromParams(request.params, addresses)) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
     }

     std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > indexes;

     if (!mempool.getAddressIndex(addresses, indexes)) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
     }

     std::sort(indexes.begin(), indexes.end(), timestampSort);

     UniValue result(UniValue::VARR);

     for (std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> >::iterator it = indexes.begin();
          it != indexes.end(); it++) {

        std::string address;
         if (!getAddressFromIndex(it->first.type, it->first.addressBytes, address)) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
         }

         UniValue delta(UniValue::VOBJ);
         delta.pushKV("address", address);
         delta.pushKV("txid", it->first.txhash.GetHex());
         delta.pushKV("index", (int)it->first.index);
         delta.pushKV("satoshis", it->second.amount);
         delta.pushKV("timestamp", it->second.time);
         if (it->second.amount < 0) {
             delta.pushKV("prevtxid", it->second.prevhash.GetHex());
             delta.pushKV("prevout", (int)it->second.prevout);
         }
         result.push_back(delta);
     }

     return result;
 }

UniValue getaddressutxos(const JSONRPCRequest& request)
 {
     if (request.fHelp || request.params.size() != 1 )
         throw std::runtime_error(
             "getaddressutxos\n"
             "\nReturns all unspent outputs for an address (requires addressindex to be enabled).\n"
             "\nResult\n"
             "[\n"
             "  {\n"
             "    \"address\"  (string) The address base58check encoded\n"
             "    \"txid\"  (string) The output txid\n"
             "    \"height\"  (number) The block height\n"
             "    \"outputIndex\"  (number) The output index\n"
             "    \"script\"  (strin) The script hex encoded\n"
             "    \"satoshis\"  (number) The number of satoshis of the output\n"
             "  }\n"
             "]\n"
             );

     std::vector<std::pair<uint160, int> > addresses;

     if (!getAddressesFromParams(request.params, addresses)) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
     }

     std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

     for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
         if (!GetAddressUnspent((*it).first, (*it).second, unspentOutputs)) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
         }
     }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

     UniValue result(UniValue::VARR);

     for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
         UniValue output(UniValue::VOBJ);
         
         std::string address;
         if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
         }

         output.pushKV("address", address);
         output.pushKV("txid", it->first.txhash.GetHex());
         output.pushKV("outputIndex", (int)it->first.index);
         output.pushKV("script", HexStr(it->second.script.begin(), it->second.script.end()));
         output.pushKV("satoshis", it->second.satoshis);
         output.pushKV("height", it->second.blockHeight);
         result.push_back(output);
     }

     return result;
 }

UniValue getaddressdeltas(const JSONRPCRequest& request)
 {
     if (request.fHelp || request.params.size() != 1 || !request.params[0].isObject())
         throw std::runtime_error(
             "getaddressdeltas\n"
             "\nReturns all changes for an address (requires addressindex to be enabled).\n"
             "\nResult\n"
             "[\n"
             "  {\n"
             "    \"satoshis\"  (number) The difference of satoshis\n"
             "    \"txid\"  (string) The related txid\n"
             "    \"index\"  (number) The related input or output index\n"
             "    \"height\"  (number) The block height\n"
             "    \"address\"  (string) The base58check encoded address\n"
             "  }\n"
             "]\n"
         );


     UniValue startValue = find_value(request.params[0].get_obj(), "start");
     UniValue endValue = find_value(request.params[0].get_obj(), "end");

     int start = 0;
     int end = 0;

     if (startValue.isNum() && endValue.isNum()) {
         start = startValue.get_int();
         end = endValue.get_int();
         if (end < start) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "End value is expected to be greater than start");
         }
     }

     std::vector<std::pair<uint160, int> > addresses;

     if (!getAddressesFromParams(request.params, addresses)) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
     }

     std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

     for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
         if (start > 0 && end > 0) {
             if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                 throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
             }
         } else {
             if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                 throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
             }
         }
     }

     UniValue result(UniValue::VARR);

     for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
         
         std::string address;
         if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
         }
         
         UniValue delta(UniValue::VOBJ);
         delta.pushKV("satoshis", it->second);
         delta.pushKV("txid", it->first.txhash.GetHex());
         delta.pushKV("index", (int)it->first.index);
         delta.pushKV("height", it->first.blockHeight);
        delta.pushKV("address", address);
         result.push_back(delta);
     }

     return result;
 }

UniValue getaddressbalance(const JSONRPCRequest& request)
 {
     if (request.fHelp || request.params.size() != 1)
         throw std::runtime_error(
             "getaddressbalance\n"
             "\nReturns the balance for an address (requires addressindex to be enabled).\n"
             "\nResult\n"
             "{\n"
             "  \"balance\"  (string) The current balance\n"
             "  ,...\n"
             "}\n"
         );

     std::vector<std::pair<uint160, int> > addresses;

     if (!getAddressesFromParams(request.params, addresses)) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
     }

     std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

     for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
         if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
         }
     }

     CAmount balance = 0;
     CAmount received = 0;

     for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        if (it->second > 0) {
             received += it->second;
         }
         balance += it->second;
     }

     UniValue result(UniValue::VOBJ);
     result.pushKV("balance", balance);
     result.pushKV("received", received);

     return result;

 }



UniValue getaddresstxids(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaddresstxids\n"
            "\nReturns the txids for an address (requires addressindex to be enabled).\n"
            "\nResult\n"
            "[\n"
            "  \"transactionid\"  (string) The transaction id\n"
            "  ,...\n"
            "]\n"
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

     int start = 0;
     int end = 0;
     if (request.params[0].isObject()) {
         UniValue startValue = find_value(request.params[0].get_obj(), "start");
         UniValue endValue = find_value(request.params[0].get_obj(), "end");
         if (startValue.isNum() && endValue.isNum()) {
             start = startValue.get_int();
             end = endValue.get_int();
         }
     }



    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
         if (start > 0 && end > 0) {
             if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                 throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
             }
         } else {
             if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                 throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
             }
        }
    }

    std::set<std::pair<int, std::string> > txids;
     UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        std::string txid = it->first.txhash.GetHex();
        if (addresses.size() > 1) {
             txids.insert(std::make_pair(height, txid));
         } else {
             if (txids.insert(std::make_pair(height, txid)).second) {
                 result.push_back(txid);
             }
         }
    }

    if (addresses.size() > 1) {
      for (std::set<std::pair<int, std::string> >::const_iterator it=txids.begin(); it!=txids.end(); it++) {
             result.push_back(it->second);
         }
    }

    return result;

}


/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total bitcoin balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

    LOCK(cs_main);


    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", CLIENT_VERSION);
    obj.pushKV("protocolversion", PROTOCOL_VERSION);

    obj.pushKV("blocks",        (int)chainActive.Height());
    obj.pushKV("timeoffset",    GetTimeOffset());
    obj.pushKV("connections",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL));
    obj.pushKV("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string()));
    obj.pushKV("difficulty",    (double)GetDifficulty());
    obj.pushKV("testnet",       (gArgs.GetChainName() == CBaseChainParams::TESTNET));

    obj.pushKV("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK()));
    obj.pushKV("errors",        GetWarnings("statusbar"));
    return obj;
}




static UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given digibyte address.\n"
            "DEPRECATION WARNING: Parts of this command have been deprecated and moved to getaddressinfo. Clients must\n"
            "transition to using getaddressinfo to access this information before upgrading to v0.18. The following deprecated\n"
            "fields have moved to getaddressinfo and will only be shown here with -deprecatedrpc=validateaddress: ismine, iswatchonly,\n"
            "script, hex, pubkeys, sigsrequired, pubkey, addresses, embedded, iscompressed, account, timestamp, hdkeypath, kdmasterkeyid.\n"
            "\nArguments:\n"
            "1. \"address\"                    (string, required) The digibyte address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\",        (string) The digibyte address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"iswitness\" : true|false,     (boolean) If the address is a witness address\n"
            "  \"witness_version\" : version   (numeric, optional) The version number of the witness program\n"
            "  \"witness_program\" : \"hex\"     (string, optional) The hex value of the witness program\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("isvalid", isValid);
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

        UniValue detail = DescribeAddress(dest);
        ret.pushKVs(detail);
    }
    return ret;
}

static UniValue createmultisig(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
    {
        std::string msg = "createmultisig nrequired [\"key\",...] ( \"address_type\" )\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"
            "\nArguments:\n"
            "1. nrequired                    (numeric, required) The number of required signatures out of the n keys.\n"
            "2. \"keys\"                       (string, required) A json array of hex-encoded public keys\n"
            "     [\n"
            "       \"key\"                    (string) The hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"
            "3. \"address_type\"               (string, optional) The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is legacy.\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 public keys\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); ++i) {
        if (IsHex(keys[i].get_str()) && (keys[i].get_str().length() == 66 || keys[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys[i].get_str()));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid public key: %s\n.", keys[i].get_str()));
        }
    }

    // Get the output type
    OutputType output_type = OutputType::LEGACY;
    if (!request.params[2].isNull()) {
        if (!ParseOutputType(request.params[2].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[2].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    const CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    CBasicKeyStore keystore;
    const CTxDestination dest = AddAndGetDestinationForScript(keystore, inner, output_type);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));

    return result;
}

static UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifymessage \"address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The digibyte address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&destination);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == *keyID);
}

static UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessagewithprivkey \"privkey\" \"message\"\n"
            "\nSign a message with the private key of an address\n"
            "\nArguments:\n"
            "1. \"privkey\"         (string, required) The private key to sign the message with.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        );

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CKey key = DecodeSecret(strPrivkey);
    if (!key.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

static UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("setmocktime for regression testing (-regtest mode) only");

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("used", uint64_t(stats.used));
    obj.pushKV("free", uint64_t(stats.free));
    obj.pushKV("total", uint64_t(stats.total));
    obj.pushKV("locked", uint64_t(stats.locked));
    obj.pushKV("chunks_used", uint64_t(stats.chunks_used));
    obj.pushKV("chunks_free", uint64_t(stats.chunks_free));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

static UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getmemoryinfo (\"mode\")\n"
            "Returns an object containing information about memory usage.\n"
            "Arguments:\n"
            "1. \"mode\" determines what kind of information is returned. This argument is optional, the default mode is \"stats\".\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+).\n"
            "\nResult (mode \"stats\"):\n"
            "{\n"
            "  \"locked\": {               (json object) Information about locked memory manager\n"
            "    \"used\": xxxxx,          (numeric) Number of bytes used\n"
            "    \"free\": xxxxx,          (numeric) Number of bytes available in current arenas\n"
            "    \"total\": xxxxxxx,       (numeric) Total number of bytes managed\n"
            "    \"locked\": xxxxxx,       (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n"
            "    \"chunks_used\": xxxxx,   (numeric) Number allocated chunks\n"
            "    \"chunks_free\": xxxxx,   (numeric) Number unused chunks\n"
            "  }\n"
            "}\n"
            "\nResult (mode \"mallocinfo\"):\n"
            "\"<malloc version=\"1\">...\"\n"
            "\nExamples:\n"
            + HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
        );

    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("locked", RPCLockedMemoryInfo());
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
}

static void EnableOrDisableLogCategories(UniValue cats, bool enable) {
    cats = cats.get_array();
    for (unsigned int i = 0; i < cats.size(); ++i) {
        std::string cat = cats[i].get_str();

        bool success;
        if (enable) {
            success = g_logger->EnableCategory(cat);
        } else {
            success = g_logger->DisableCategory(cat);
        }

        if (!success) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
    }
}

UniValue logging(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "logging ( <include> <exclude> )\n"
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + ListLogCategories() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            "  - \"none\", \"0\" : even if other logging categories are specified, ignore all of them.\n"
            "\nArguments:\n"
            "1. \"include\"        (array of strings, optional) A json array of categories to add debug logging\n"
            "     [\n"
            "       \"category\"   (string) the valid logging category\n"
            "       ,...\n"
            "     ]\n"
            "2. \"exclude\"        (array of strings, optional) A json array of categories to remove debug logging\n"
            "     [\n"
            "       \"category\"   (string) the valid logging category\n"
            "       ,...\n"
            "     ]\n"
            "\nResult:\n"
            "{                   (json object where keys are the logging categories, and values indicates its status\n"
            "  \"category\": 0|1,  (numeric) if being debug logged or not. 0:inactive, 1:active\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], \"[libevent]\"")
        );
    }

    uint32_t original_log_categories = g_logger->GetCategoryMask();
    if (request.params[0].isArray()) {
        EnableOrDisableLogCategories(request.params[0], true);
    }
    if (request.params[1].isArray()) {
        EnableOrDisableLogCategories(request.params[1], false);
    }
    uint32_t updated_log_categories = g_logger->GetCategoryMask();
    uint32_t changed_log_categories = original_log_categories ^ updated_log_categories;

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    if (changed_log_categories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(g_logger->WillLogCategory(BCLog::LIBEVENT))) {
            g_logger->DisableCategory(BCLog::LIBEVENT);
            if (changed_log_categories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    std::vector<CLogCategoryActive> vLogCatActive = ListActiveLogCategories();
    for (const auto& logCatActive : vLogCatActive) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
}

static UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "echo|echojson \"message\" ...\n"
            "\nSimply echo back the input arguments. This command is for testing.\n"
            "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in"
            "digibyte-cli and the GUI. There is no server-side difference."
        );

    return request.params;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------

    /* Address index */
    { "addressindex",       "getaddressmempool",      &getaddressmempool,      {"addresses"} } ,
    { "addressindex",       "getaddressutxos",        &getaddressutxos,       {"addresses"} },
    { "addressindex",       "getaddressdeltas",       &getaddressdeltas,       {"addresses","start","end"} },
    { "addressindex",       "getaddresstxids",        &getaddresstxids,        {"addresses"} },
    { "addressindex",       "getaddressbalance",      &getaddressbalance,      {"addresses"} },

    { "control",            "getmemoryinfo",          &getmemoryinfo,          {"mode"} },
    { "control",            "logging",                &logging,                {"include", "exclude"}},
    { "control",            "getinfo",                &getinfo,                {}  },
    { "util",               "validateaddress",        &validateaddress,        {"address"} },
    { "util",               "createmultisig",         &createmultisig,         {"nrequired","keys","address_type"} },
    { "util",               "verifymessage",          &verifymessage,          {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, {"privkey","message"} },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            {"timestamp"}},
    { "hidden",             "echo",                   &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
};
// clang-format on

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
