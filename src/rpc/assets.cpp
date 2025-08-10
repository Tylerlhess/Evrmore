// Copyright (c) 2017-2021 The Raven Core developers
// Copyright (c) 2022 The Evrmore Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/assets.h"
#include "assets/assetdb.h"
#include <map>
#include "tinyformat.h"

#include "base58.h"
#include "chain.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "httpserver.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "policy/rbf.h"
#include "rpc/assets.h"
#include "rpc/mining.h"
#include "rpc/safemode.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet/coincontrol.h"
#include "wallet/feebumper.h"
#include "wallet/wallet.h"
#include "base58.h"
#include "wallet/walletdb.h"

void CheckRestrictedAssetTransferInputs(const CWalletTx& transaction, const std::string& asset_name) {
    // Do a validity check before commiting the transaction
    if (IsAssetNameAnRestricted(asset_name)) {
        if (pcoinsTip && passets) {
            for (auto input : transaction.tx->vin) {
                const COutPoint &prevout = input.prevout;
                const Coin &coin = pcoinsTip->AccessCoin(prevout);

                if (coin.IsAsset()) {
                    CAssetOutputEntry data;
                    if (!GetAssetData(coin.out.scriptPubKey, data))
                        throw JSONRPCError(RPC_DATABASE_ERROR, std::string(
                                _("Unable to get coin to verify restricted asset transfer from address")));


                    if (IsAssetNameAnRestricted(data.assetName)) {
                        if (passets->CheckForAddressRestriction(data.assetName, EncodeDestination(data.destination),
                                                                true)) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(
                                    _("Restricted asset transfer from address that has been frozen")));
                        }
                    }
                }
            }
        }
    }
}

std::string AssetActivationWarning()
{
    return AreAssetsDeployed() ? "" : "\nTHIS COMMAND IS NOT YET ACTIVE!\nhttps://github.com/RavenProject/rips/blob/master/rip-0002.mediawiki\n";
}

std::string RestrictedActivationWarning()
{
    return AreRestrictedAssetsDeployed() ? "" : "\nTHIS COMMAND IS NOT YET ACTIVE! Restricted assets must be active\n\n";
}

std::string AssetTypeToString(AssetType& assetType)
{
    switch (assetType)
    {
        case AssetType::ROOT:               return "ROOT";
        case AssetType::SUB:                return "SUB";
        case AssetType::UNIQUE:             return "UNIQUE";
        case AssetType::OWNER:              return "OWNER";
        case AssetType::MSGCHANNEL:         return "MSGCHANNEL";
        case AssetType::VOTE:               return "VOTE";
        case AssetType::REISSUE:            return "REISSUE";
        case AssetType::REISSUE_METADATA:   return "REISSUE_METADATA";
        case AssetType::REMINTING:          return "REMINTING";
        case AssetType::QUALIFIER:          return "QUALIFIER";
        case AssetType::SUB_QUALIFIER:      return "SUB_QUALIFIER";
        case AssetType::RESTRICTED:         return "RESTRICTED";
        case AssetType::INVALID:            return "INVALID";
        default:                            return "UNKNOWN";
    }
}

UniValue UnitValueFromAmount(const CAmount& amount, const std::string asset_name)
{

    auto currentActiveAssetCache = GetCurrentAssetCache();
    if (!currentActiveAssetCache)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Asset cache isn't available.");

    uint8_t units = OWNER_UNITS;
    if (!IsAssetNameAnOwner(asset_name)) {
        CNewAsset assetData;
        if (!currentActiveAssetCache->GetAssetMetaDataIfExists(asset_name, assetData))
            units = MAX_UNIT;
            //throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't load asset from cache: " + asset_name);
        else
            units = assetData.units;
    }

    return ValueFromAmount(amount, units);
}

#ifdef ENABLE_WALLET
UniValue UpdateAddressTag(const JSONRPCRequest &request, const int8_t &flag)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Check asset name and infer assetType
    std::string tag_name = request.params[0].get_str();

    if (!IsAssetNameAQualifier(tag_name)) {
        std::string temp = QUALIFIER_CHAR + tag_name;

        auto index = temp.find("/");
        if (index != std::string::npos) {
            temp.insert(index+1, "#");
        }
        tag_name = temp;
    }

    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameValid(tag_name, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + tag_name + std::string("\nError: ") + assetError);
    }

    if (assetType != AssetType::QUALIFIER && assetType != AssetType::SUB_QUALIFIER) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unsupported asset type: ") + AssetTypeToString(assetType));
    }

    std::string address = request.params[1].get_str();
    CTxDestination destination = DecodeDestination(address);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + address);
    }

    // Get the optional change address
    std::string change_address = "";
    if (request.params.size() > 2) {
        change_address = request.params[2].get_str();
        if (!change_address.empty()) {
           CTxDestination change_dest = DecodeDestination(change_address);
           if (!IsValidDestination(change_dest)) {
               throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore change address: ") + change_address);
           }
        }
    }

    // Get the optional asset data
    std::string asset_data = "";
    if (request.params.size() > 3) {
        asset_data = request.params[3].get_str();
        asset_data = DecodeAssetData(asset_data);

        if (asset_data.empty())
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset data hash"));
    }

    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    CCoinControl ctrl;

    ctrl.destChange = DecodeDestination(change_address);

    // If the optional change address wasn't given create a new change address for this wallet
    if (change_address == "") {
        CKeyID keyID;
        std::string strFailReason;
        if (!pwallet->CreateNewChangeAddress(reservekey, keyID, strFailReason))
            throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);

        change_address = EncodeDestination(keyID);
    }

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    // Always transfer 1 of the qualifier tokens to the change address
    vTransfers.emplace_back(std::make_pair(CAssetTransfer(tag_name, 1 * COIN, asset_data), change_address));

    // Add the asset data with the flag to remove or add the tag 1 = Add, 0 = Remove
    std::vector< std::pair<CNullAssetTxData, std::string> > vecAssetData;
    vecAssetData.push_back(std::make_pair(CNullAssetTxData(tag_name, flag), address));

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee, &vecAssetData))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue UpdateAddressRestriction(const JSONRPCRequest &request, const int8_t &flag)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Check asset name and infer assetType
    std::string restricted_name = request.params[0].get_str();

    if (!IsAssetNameAnRestricted(restricted_name)) {
        std::string temp = RESTRICTED_CHAR + restricted_name;
        restricted_name = temp;
    }

    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameValid(restricted_name, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + restricted_name + std::string("\nError: ") + assetError);
    }

    if (assetType != AssetType::RESTRICTED) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unsupported asset type: ") + AssetTypeToString(assetType));
    }

    std::string address = request.params[1].get_str();
    CTxDestination destination = DecodeDestination(address);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + address);
    }

    // Get the optional change address
    std::string change_address = "";
    if (request.params.size() > 2) {
        change_address = request.params[2].get_str();
        if (!change_address.empty()) {
           CTxDestination change_dest = DecodeDestination(change_address);
           if (!IsValidDestination(change_dest)) {
               throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore change address: ") + change_address);
           }
        }
    }

    // Get the optional asset data
    std::string asset_data = "";
    if (request.params.size() > 3) {
        asset_data = request.params[3].get_str();
        asset_data = DecodeAssetData(asset_data);

        if (asset_data.empty())
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset data hash"));
    }

    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    CCoinControl ctrl;

    // If the optional change address wasn't given create a new change address for this wallet
    if (change_address == "") {
        CKeyID keyID;
        std::string strFailReason;
        if (!pwallet->CreateNewChangeAddress(reservekey, keyID, strFailReason))
            throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);

        change_address = EncodeDestination(keyID);
    }

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    // Always transfer 1 of the restricted tokens to the change address
    // Use the ROOT owner token to make this change occur. if $TOKEN -> Use TOKEN!
    vTransfers.emplace_back(std::make_pair(CAssetTransfer(restricted_name.substr(1, restricted_name.size()) + OWNER_TAG, 1 * COIN, asset_data), change_address));

    // Add the asset data with the flag to remove or add the tag 1 = Freeze, 0 = Unfreeze
    std::vector< std::pair<CNullAssetTxData, std::string> > vecAssetData;
    vecAssetData.push_back(std::make_pair(CNullAssetTxData(restricted_name.substr(0, restricted_name.size()), flag), address));

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee, &vecAssetData))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}


UniValue UpdateGlobalRestrictedAsset(const JSONRPCRequest &request, const int8_t &flag)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Check asset name and infer assetType
    std::string restricted_name = request.params[0].get_str();

    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameValid(restricted_name, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + restricted_name + std::string("\nError: ") + assetError);
    }

    if (assetType != AssetType::RESTRICTED) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unsupported asset type: ") + AssetTypeToString(assetType));
    }

    if (flag == 1 && mempool.mapGlobalFreezingAssetTransactions.count(restricted_name)){
        throw JSONRPCError(RPC_TRANSACTION_REJECTED, std::string("Freezing transaction already in mempool"));
    }

    if (flag == 0 && mempool.mapGlobalUnFreezingAssetTransactions.count(restricted_name)){
        throw JSONRPCError(RPC_TRANSACTION_REJECTED, std::string("Unfreezing transaction already in mempool"));
    }

    // Get the optional change address
    std::string change_address = "";
    if (request.params.size() > 1) {
        change_address = request.params[1].get_str();
        if (!change_address.empty()) {
           CTxDestination change_dest = DecodeDestination(change_address);
           if (!IsValidDestination(change_dest)) {
               throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore change address: ") + change_address);
           }
        }
    }

    // Get the optional asset data
    std::string asset_data = "";
    if (request.params.size() > 2) {
        asset_data = request.params[2].get_str();
        asset_data = DecodeAssetData(asset_data);

        if (asset_data.empty())
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset data hash"));
    }

    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    CCoinControl ctrl;

    // If the optional change address wasn't given create a new change address for this wallet
    if (change_address == "") {
        CKeyID keyID;
        std::string strFailReason;
        if (!pwallet->CreateNewChangeAddress(reservekey, keyID, strFailReason))
            throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);

        change_address = EncodeDestination(keyID);
    }

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    // Always transfer 1 of the restricted tokens to the change address
    // Use the ROOT owner token to make this change occur. if $TOKEN -> Use TOKEN!
    vTransfers.emplace_back(std::make_pair(CAssetTransfer(restricted_name.substr(1, restricted_name.size()) + OWNER_TAG, 1 * COIN, asset_data), change_address));

    // Add the global asset data, 1 = Freeze all transfers, 0 = Allow transfers
    std::vector<CNullAssetTxData> vecGlobalAssetData;
    vecGlobalAssetData.push_back(CNullAssetTxData(restricted_name.substr(0, restricted_name.size()), flag));

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee, nullptr, &vecGlobalAssetData))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

void assetToJSON(const CNewAsset& asset, UniValue& result)
{
    AddBaseAssetInfoToUniValue(asset, result);
    AddIpfsInfoToUniValue(asset, result);
    if (GetCurrentAssetCache() != nullptr) {
        CNullAssetTxVerifierString verifier;
        if (GetCurrentAssetCache()->GetAssetVerifierStringIfExists(asset.strName, verifier)) {
            result.push_back(Pair("verifier_string", verifier.verifier_string));
        }
    }

    AddTollAssetInfoToUniValue(asset, result);
}

void AddBaseAssetInfoToUniValue(const CNewAsset& asset, UniValue& result)
{
    result.push_back(Pair("version", AssetVersionToString(asset.nVersion)));
    result.push_back(Pair("name", asset.strName));
    result.push_back(Pair("amount", UnitValueFromAmount(asset.nAmount, asset.strName)));
    result.push_back(Pair("units", asset.units));
    result.push_back(Pair("reissuable", asset.nReissuable));
    result.push_back(Pair("has_ipfs", asset.nHasIPFS));

    AddIpfsInfoToUniValue(asset, result);
}

void AddTollAssetInfoToUniValue(const CNewAsset& asset, UniValue& result)
{
    result.push_back(Pair("toll_amount_mutability", asset.nTollAmountMutability));
    result.push_back(Pair("toll_amount", ValueFromAmount(asset.nTollAmount)));
    result.push_back(Pair("toll_address_mutability", asset.nTollAddressMutability));
    result.push_back(Pair("toll_address", asset.strTollAddress));
    result.push_back(Pair("remintable", asset.nRemintable));
    result.push_back(Pair("burned_total", ValueFromAmount(asset.nTotalBurned)));
    result.push_back(Pair("currently_burned", ValueFromAmount(asset.nCurrentlyBurned)));
    result.push_back(Pair("reminted_total", ValueFromAmount(asset.nTotalBurned - asset.nCurrentlyBurned)));
}

void AddIpfsInfoToUniValue(const CNewAsset& asset, UniValue& result) {

    bool fShowPermanent = true;

    if (asset.nHasIPFS) {
        if (IsTollsActive()) {
            // Certain criteria met, showing what the permanent hash is going to be
            if (asset.nVersion == STANDARD_VERSION && !asset.nReissuable) {
                fShowPermanent = false;
                if (asset.strPermanentIPFSHash.size() == 32) {
                    result.push_back(Pair("permanent_txid", EncodeAssetData(asset.strIPFSHash)));
                } else {
                    result.push_back(Pair("permanent_ipfs_hash", EncodeAssetData(asset.strIPFSHash)));
                }
            }

            // Always show current ipfs
            if (asset.strIPFSHash.size() == 32) {
                result.push_back(Pair("txid", EncodeAssetData(asset.strIPFSHash)));
            } else {
                result.push_back(Pair("ipfs_hash", EncodeAssetData(asset.strIPFSHash)));
            }
        } else {
            if (asset.strIPFSHash.size() == 32) {
                result.push_back(Pair("txid", EncodeAssetData(asset.strIPFSHash)));
            } else {
                result.push_back(Pair("ipfs_hash", EncodeAssetData(asset.strIPFSHash)));
            }
        }
    }

    if (fShowPermanent) {
        if (asset.strPermanentIPFSHash.size() == 32) {
            result.push_back(Pair("permanent_txid", EncodeAssetData(asset.strPermanentIPFSHash)));
        } else {
            result.push_back(Pair("permanent_ipfs_hash", EncodeAssetData(asset.strPermanentIPFSHash)));
        }
    }
}

UniValue issue(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 1 || request.params.size() > 14)
        throw std::runtime_error(
            "issue \"asset_name\" qty \"( to_address )\" \"( change_address )\" ( units ) ( reissuable ) ( has_ipfs ) \"( ipfs_hash )\" \"( permanent_ipfs_hash )\" ( toll_amount ) \"( toll_address ) ( toll_amount_mutability ) ( toll_address_mutability ) ( remintable )\"\n"
            + AssetActivationWarning() +
            "\nIssue an asset, subasset or unique asset.\n"
            "Asset name must not conflict with any existing asset.\n"
            "Unit as the number of decimals precision for the asset (0 for whole units (\"1\"), 8 for max precision (\"1.00000000\")\n"
            "Reissuable is true/false for whether additional units can be issued by the original issuer.\n"
            "If issuing a unique asset these values are required (and will be defaulted to): qty=1, units=0, reissuable=false.\n"

            "\nArguments:\n"
            "1. \"asset_name\"            (string, required) a unique name\n"
            "2. \"qty\"                   (numeric, optional, default=1) the number of units to be issued\n"
            "3. \"to_address\"            (string), optional, default=\"\"), address asset will be sent to, if it is empty, address will be generated for you\n"
            "4. \"change_address\"        (string), optional, default=\"\"), address the evr change will be sent to, if it is empty, change address will be generated for you\n"
            "5. \"units\"                 (integer, optional, default=0, min=0, max=8), the number of decimals precision for the asset (0 for whole units (\"1\"), 8 for max precision (\"1.00000000\")\n"
            "6. \"reissuable\"            (boolean, optional, default=true (false for unique assets)), whether future reissuance is allowed\n"
            "7. \"has_ipfs\"              (boolean, optional, default=false), whether ipfs hash is going to be added to the asset\n"
            "8. \"ipfs_hash\"             (string, optional but required if has_ipfs = 1), an ipfs hash or a txid hash once RIP5 is activated\n"
            "9. \"permanent_ipfs_hash\"  (string, optional) a permanent IPFS hash for the asset\n"
            "10. \"toll_amount\"           (numeric, optional, default=0), the amount of toll fee to be assigned to the asset\n"
            "11. \"toll_address\"          (string, optional, default=\"\"), address to receive the toll fee, if it is empty, the default toll address will be used\n"
            "12. \"toll_amount_mutability\" (boolean, optional, default=false), whether future changing is allowed for the toll amount\n"
            "13. \"toll_address_mutability\" (boolean, optional, default=false), whether future changing is allowed for the toll address\n"
            "14. \"remintable\"              (boolean, optional, default=true), whether the ability to remint assets that are burned is allowed\n"

            "\nResult:\n"
            "\"txid\"                     (string) The transaction id\n"

            "\nExamples:\n"
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\"")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" 4")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" 2 true")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" 8 false true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E 0.01 \"tollAddress\" true true")
            + HelpExampleCli("issue", "\"ASSET_NAME/SUB_ASSET\" 1000 \"myaddress\" \"changeaddress\" 2 true")
            + HelpExampleCli("issue", "\"ASSET_NAME#uniquetag\"")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Check asset name and infer assetType
    std::string assetName = request.params[0].get_str();
    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameValid(assetName, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + assetName + std::string("\nError: ") + assetError);
    }

    // Push the user to use the issue restricted rpc call if they are trying to issue a restricted asset
    if (assetType == AssetType::RESTRICTED) {
        throw (JSONRPCError(RPC_INVALID_PARAMETER, std::string("Use the rpc call issuerestricted to issue a restricted asset")));
    }

    // Push the user to use the issue restricted rpc call if they are trying to issue a restricted asset
    if (assetType == AssetType::QUALIFIER || assetType == AssetType::SUB_QUALIFIER) {
        throw (JSONRPCError(RPC_INVALID_PARAMETER, std::string("Use the rpc call issuequalifierasset to issue a qualifier asset")));
    }

    // Check for unsupported asset types
    if (assetType == AssetType::VOTE || assetType == AssetType::REISSUE || assetType == AssetType::OWNER || assetType == AssetType::INVALID) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unsupported asset type: ") + AssetTypeToString(assetType));
    }

    CAmount nAmount = COIN;
    if (request.params.size() > 1)
        nAmount = AmountFromValue(request.params[1]);

    std::string address = "";
    if (request.params.size() > 2)
        address = request.params[2].get_str();

    if (!address.empty()) {
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + address);
        }
    } else {
        // Create a new address
        std::string strAccount;

        if (!pwallet->IsLocked()) {
            pwallet->TopUpKeyPool();
        }

        // Generate a new key that is added to wallet
        CPubKey newKey;
        if (!pwallet->GetKeyFromPool(newKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        }
        CKeyID keyID = newKey.GetID();

        pwallet->SetAddressBook(keyID, strAccount, "receive");

        address = EncodeDestination(keyID);
    }

    std::string change_address = "";
    if (request.params.size() > 3) {
        change_address = request.params[3].get_str();
        if (!change_address.empty()) {
            CTxDestination destination = DecodeDestination(change_address);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Change Address: Invalid Evrmore address: ") + change_address);
            }
        }
    }

    int units = 0;
    if (request.params.size() > 4)
        units = request.params[4].get_int();

    bool reissuable = assetType != AssetType::UNIQUE && assetType != AssetType::MSGCHANNEL && assetType != AssetType::QUALIFIER && assetType != AssetType::SUB_QUALIFIER;
    if (request.params.size() > 5)
        reissuable = request.params[5].get_bool();

    bool has_ipfs = false;
    if (request.params.size() > 6)
        has_ipfs = request.params[6].get_bool();

    // Check the ipfs
    std::string ipfs_hash = "";
    bool fMessageCheck = false;
    if (request.params.size() > 7 && has_ipfs) {
        fMessageCheck = true;
        ipfs_hash = request.params[7].get_str();
    }

    // New field: second IPFS hash
    bool fCheckPermanent = false;
    std::string permanent_ipfs_hash = "";
    if (request.params.size() > 8) {
        permanent_ipfs_hash = request.params[8].get_str();
        if (permanent_ipfs_hash.size() > 0)
            fCheckPermanent = true;
    }

    // New field: toll amount
    CAmount toll_amount = 0;
    if (request.params.size() > 9) {
        toll_amount = AmountFromValue(request.params[9]);
    }

    // New field: toll address
    std::string toll_address = "";
    if (request.params.size() > 10) {
        toll_address = request.params[10].get_str();
        if (!toll_address.empty()) {
            CTxDestination destination = DecodeDestination(toll_address);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Toll Address: Invalid Evrmore address: ") + toll_address);
            }
        }
    }

    bool toll_amount_mutability = true;
    if (request.params.size() > 11) {
        toll_amount_mutability = request.params[11].get_bool();
    }

    bool toll_address_mutability = true;
    if (request.params.size() > 12) {
        toll_address_mutability = request.params[12].get_bool();
    }

    bool remintable = true;
    if (request.params.size() > 13) {
        remintable = request.params[13].get_bool();
    }

    // Reissues don't have an expire time
    int64_t expireTime = 0;

    // Check the message data
    if (fMessageCheck)
        CheckIPFSTxidMessage(ipfs_hash, expireTime);

    if (fCheckPermanent)
        CheckIPFSTxidMessage(permanent_ipfs_hash, expireTime);

    // Check for required unique asset params
    if ((assetType == AssetType::UNIQUE || assetType == AssetType::MSGCHANNEL) && (nAmount != COIN || units != 0 || reissuable)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters for issuing a unique asset."));
    }

    // Check for required qualifier asset params
    if ((assetType == AssetType::QUALIFIER || assetType == AssetType::SUB_QUALIFIER) && (nAmount < QUALIFIER_ASSET_MIN_AMOUNT || nAmount > QUALIFIER_ASSET_MAX_AMOUNT  || units != 0 || reissuable)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters for issuing a qualifier asset."));
    }

    // Adding remintable as a flag, changes the version of the asset to version 2 if it is set to true
    // Which is the default value. If tolls isn't live, change to false before creating the asset object to
    // retain version 1 backwards compatibility.
    if (!IsTollsActive()) {
        remintable = false;
    }

    CNewAsset asset(assetName, nAmount, units, reissuable ? 1 : 0, has_ipfs ? 1 : 0, DecodeAssetData(ipfs_hash), DecodeAssetData(permanent_ipfs_hash), toll_amount, toll_address, toll_amount_mutability, toll_address_mutability, remintable);

    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    std::pair<int, std::string> error;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(change_address);

    // Create the Transaction
    if (!CreateAssetTransaction(pwallet, crtl, asset, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue issueunique(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 2 || request.params.size() > 10)
        throw std::runtime_error(
                "issueunique \"root_name\" [asset_tags] ( [ipfs_hashes] ) \"( to_address )\" \"( change_address )\"  ( [permanent_ipfs_hashes] ) \"( toll_address )\" ( toll_amount ) ( toll_amount_mutability ) ( toll_address_mutability )\n"
                + AssetActivationWarning() +
                "\nIssue unique asset(s).\n"
                "root_name must be an asset you own.\n"
                "An asset will be created for each element of asset_tags.\n"
                "If provided ipfs_hashes must be the same length as asset_tags.\n"
                "Five (5) EVR will be burned for each asset created.\n"

                "\nArguments:\n"
                "1. \"root_name\"             (string, required) name of the asset the unique asset(s) are being issued under\n"
                "2. \"asset_tags\"            (array, required) the unique tag for each asset which is to be issued\n"
                "3. \"ipfs_hashes\"           (array, optional) ipfs hashes or txid hashes corresponding to each supplied tag (should be same size as \"asset_tags\")\n"
                "4. \"to_address\"            (string, optional, default=\"\"), address assets will be sent to, if it is empty, address will be generated for you\n"
                "5. \"change_address\"        (string, optional, default=\"\"), address the the evr change will be sent to, if it is empty, change address will be generated for you\n"
                "6. \"permanent_ipfs_hashes\" (array, optional) permanent ipfs hashes or txid hashes corresponding to each supplied tag (should be same size as \"asset_tags\")\n"
                "7. \"toll_address\"          (string, optional, default=\"\"), address for tolls to be paid to\n"
                "8. \"toll_amount\"           (number, optional, default=0), toll amount to be paid when an asset is transferred\n"
                "9. \"toll_amount_mutability\" (boolean, optional, default=false), whether future changing is allowed for the toll amount\n"
                "10. \"toll_address_mutability\" (boolean, optional, default=false), whether future changing is allowed for the toll address\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("issueunique", "\"MY_ASSET\" \'[\"primo\",\"secundo\"]\'")
                + HelpExampleCli("issueunique", "\"MY_ASSET\" \'[\"primo\",\"secundo\"]\' \'[\"first_hash\",\"second_hash\"]\'")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);


    const std::string rootName = request.params[0].get_str();
    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameValid(rootName, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + rootName  + std::string("\nError: ") + assetError);
    }
    if (assetType != AssetType::ROOT && assetType != AssetType::SUB) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Root asset must be a regular top-level or sub-asset."));
    }

    const UniValue& assetTags = request.params[1];
    if (!assetTags.isArray() || assetTags.size() < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Asset tags must be a non-empty array."));
    }

    const UniValue& ipfsHashes = request.params[2];
    if (!ipfsHashes.isNull()) {
        if (!ipfsHashes.isArray() || (ipfsHashes.size() != assetTags.size() && ipfsHashes.size() != 0)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("If provided, IPFS hashes must be an array of the same size as the asset tags array."));
        }
    }

    std::string address = "";
    if (request.params.size() > 3)
        address = request.params[3].get_str();

    if (!address.empty()) {
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + address);
        }
    } else {
        // Create a new address
        std::string strAccount;

        if (!pwallet->IsLocked()) {
            pwallet->TopUpKeyPool();
        }

        // Generate a new key that is added to wallet
        CPubKey newKey;
        if (!pwallet->GetKeyFromPool(newKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        }
        CKeyID keyID = newKey.GetID();

        pwallet->SetAddressBook(keyID, strAccount, "receive");

        address = EncodeDestination(keyID);
    }

    std::string changeAddress = "";
    if (request.params.size() > 4)
        changeAddress = request.params[4].get_str();
    if (!changeAddress.empty()) {
        CTxDestination destination = DecodeDestination(changeAddress);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               std::string("Invalid Change Address: Invalid Evrmore address: ") + changeAddress);
        }
    }

    // New parameters
    UniValue permanentIpfsHashes = request.params.size() > 5 ? request.params[5] : UniValue(UniValue::VNULL);
    std::string tollAddress = request.params.size() > 6 ? request.params[6].get_str() : "";
    CAmount tollAmount = request.params.size() > 7 ? AmountFromValue(request.params[7]) : 0;
    bool toll_amount_mutability = request.params.size() > 8 ? request.params[8].get_bool() : true;
    bool toll_address_mutability = request.params.size() > 9 ? request.params[9].get_bool() : true;

    if (!permanentIpfsHashes.isNull()) {
        if (!permanentIpfsHashes.isArray() || (permanentIpfsHashes.size() != assetTags.size() && permanentIpfsHashes.size() != 0)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Permanent IPFS hashes must be the same size as asset tags.");
        }
    }

    if (!tollAddress.empty()) {
        CTxDestination destination = DecodeDestination(tollAddress);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid toll address.");
        }
    }

    std::vector<CNewAsset> assets;
    for (size_t i = 0; i < (size_t)assetTags.size(); i++) {
        std::string tag = assetTags[i].get_str();

        if (!IsUniqueTagValid(tag)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unique asset tag is invalid: " + tag));
        }

        std::string assetName = GetUniqueAssetName(rootName, tag);
        CNewAsset asset;

        // Process regular ipfs hashes
        std::string tempIpfsHash = "";
        if (!ipfsHashes.isNull() && i < ipfsHashes.size()) {
            if (!ipfsHashes[i].get_str().empty()) {
                tempIpfsHash = ipfsHashes[i].get_str();
            }
        }

        // Process permanent ipfs hashes
        std::string tempPermanentIpfsHash = "";
        if (!permanentIpfsHashes.isNull() && i < permanentIpfsHashes.size()) {
            if (!permanentIpfsHashes[i].get_str().empty()) {
                tempPermanentIpfsHash = permanentIpfsHashes[i].get_str();
            }
        }

        std::string ipfsHash = tempIpfsHash.empty() ? "" : DecodeAssetData(tempIpfsHash);
        std::string permanentIpfsHash = tempPermanentIpfsHash.empty() ? "" : DecodeAssetData(tempPermanentIpfsHash);

        asset = CNewAsset(assetName, UNIQUE_ASSET_AMOUNT, UNIQUE_ASSET_UNITS, UNIQUE_ASSETS_REISSUABLE, ipfsHash.empty() ? 0 : 1,
                  ipfsHash, permanentIpfsHash, tollAmount, tollAddress, toll_amount_mutability, toll_address_mutability, UNIQUE_ASSETS_REMINTABLE);

        assets.push_back(asset);
    }

    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    std::pair<int, std::string> error;

    CCoinControl crtl;

    crtl.destChange = DecodeDestination(changeAddress);

    // Create the Transaction
    if (!CreateAssetTransaction(pwallet, crtl, assets, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}
#endif

UniValue listassetbalancesbyaddress(const JSONRPCRequest& request)
{
    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 1)
        throw std::runtime_error(
            "listassetbalancesbyaddress \"address\" (onlytotal) (count) (start)\n"
            + AssetActivationWarning() +
            "\nReturns a list of all asset balances for an address.\n"

            "\nArguments:\n"
            "1. \"address\"                  (string, required) a Evrmore address\n"
            "2. \"onlytotal\"                (boolean, optional, default=false) when false result is just a list of assets balances -- when true the result is just a single number representing the number of assets\n"
            "3. \"count\"                    (integer, optional, default=50000, MAX=50000) truncates results to include only the first _count_ assets found\n"
            "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"

            "\nResult:\n"
            "{\n"
            "  (asset_name) : (quantity),\n"
            "  ...\n"
            "}\n"


            "\nExamples:\n"
            + HelpExampleCli("listassetbalancesbyaddress", "\"myaddress\" false 2 0")
            + HelpExampleCli("listassetbalancesbyaddress", "\"myaddress\" true")
            + HelpExampleCli("listassetbalancesbyaddress", "\"myaddress\"")
        );

    ObserveSafeMode();

    std::string address = request.params[0].get_str();
    CTxDestination destination = DecodeDestination(address);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + address);
    }

    bool fOnlyTotal = false;
    if (request.params.size() > 1)
        fOnlyTotal = request.params[1].get_bool();

    size_t count = INT_MAX;
    if (request.params.size() > 2) {
        if (request.params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = request.params[2].get_int();
    }

    long start = 0;
    if (request.params.size() > 3) {
        start = request.params[3].get_int();
    }

    if (!passetsdb)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "asset db unavailable.");

    LOCK(cs_main);
    std::vector<std::pair<std::string, CAmount> > vecAssetAmounts;
    int nTotalEntries = 0;
    if (!passetsdb->AddressDir(vecAssetAmounts, nTotalEntries, fOnlyTotal, address, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve address asset directory.");

    // If only the number of addresses is wanted return it
    if (fOnlyTotal) {
        return nTotalEntries;
    }

    UniValue result(UniValue::VOBJ);
    for (auto& pair : vecAssetAmounts) {
        result.push_back(Pair(pair.first, UnitValueFromAmount(pair.second, pair.first)));
    }

    return result;
}

UniValue getassetdata(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() != 1)
        throw std::runtime_error(
                "getassetdata \"asset_name\"\n"
                + AssetActivationWarning() +
                "\nReturns assets metadata if that asset exists\n"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) the name of the asset\n"

                "\nResult:\n"
                "{\n"
                "  version: (string),\n"
                "  name: (string),\n"
                "  amount: (number),\n"
                "  units: (number),\n"
                "  reissuable: (number),\n"
                "  has_ipfs: (number),\n"
                "  ipfs_hash: (hash), (only if has_ipfs = 1 and that data is a ipfs hash)\n"
                "  txid_hash: (hash), (only if has_ipfs = 1 and that data is a txid hash)\n"
                "  verifier_string: (string)\n"
                "  permanent_ipfs_hash: (hash), (only if it has been assigned and that data is a ipfs hash)\n"
                "  permanent_txid_hash: (hash), (only if it has been assigned and that data is a txid hash)\n"
                "  toll_amount_mutability: (number),\n"
                "  toll_amount: (number),\n"
                "  toll_address_mutability: (number),\n"
                "  toll_address: (string),\n"
                "  remintable: (number),\n"
                "  total_burned: (number),\n"
                "  currently_burned: (number),\n"
                "  reminted_total: (number),\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getassetdata", "\"ASSET_NAME\"")
                + HelpExampleRpc("getassetdata", "\"ASSET_NAME\"")
        );

    std::string asset_name = request.params[0].get_str();

    LOCK(cs_main);
    UniValue result (UniValue::VOBJ);

    auto currentActiveAssetCache = GetCurrentAssetCache();
    if (currentActiveAssetCache) {
        CNewAsset asset;
        if (!currentActiveAssetCache->GetAssetMetaDataIfExists(asset_name, asset))
            return NullUniValue;

        assetToJSON(asset, result);

        return result;
    }

    return NullUniValue;
}

UniValue getburnaddresses(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "getburnaddresses\n"
                "\nReturns a list of all burn addresses the chain uses\n"

                "\nResult:\n"
                "[\n"
                "  nickname: address (string),\n"
                "  nickname: address,\n"
                "  nickname: address,\n"
                "  etc\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("getburnaddresses", "")
                + HelpExampleRpc("getburnaddresses", "")
        );

    LOCK(cs_main);
    UniValue result (UniValue::VOBJ);

    // Add all burn addresses using the pushKV function
    result.pushKV("issue_asset", GetParams().IssueAssetBurnAddress());
    result.pushKV("issue_sub_asset", GetParams().IssueSubAssetBurnAddress());
    result.pushKV("issue_unique_asset", GetParams().IssueUniqueAssetBurnAddress());
    result.pushKV("issue_msg_channel_asset", GetParams().IssueMsgChannelAssetBurnAddress());
    result.pushKV("issue_qualifier_asset", GetParams().IssueQualifierAssetBurnAddress());
    result.pushKV("issue_sub_qualifier_asset", GetParams().IssueSubQualifierAssetBurnAddress());
    result.pushKV("issue_restricted_asset", GetParams().IssueRestrictedAssetBurnAddress());
    result.pushKV("reissue_or_remint_asset", GetParams().ReissueAssetBurnAddress());
    result.pushKV("add_null_qualifier_tag", GetParams().AddNullQualifierTagBurnAddress());
    result.pushKV("global_burn_address", GetParams().GlobalBurnAddress());
    result.pushKV("burn_mint_address", GetParams().BurnMintAddress());

    return result;
}

template <class Iter, class Incr>
void safe_advance(Iter& curr, const Iter& end, Incr n)
{
    size_t remaining(std::distance(curr, end));
    if (remaining < n)
    {
        n = remaining;
    }
    std::advance(curr, n);
};

#ifdef ENABLE_WALLET
UniValue listmyassets(const JSONRPCRequest &request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() > 5)
        throw std::runtime_error(
                "listmyassets \"( asset )\" ( verbose ) ( count ) ( start ) (confs) \n"
                + AssetActivationWarning() +
                "\nReturns a list of all asset that are owned by this wallet\n"

                "\nArguments:\n"
                "1. \"asset\"                    (string, optional, default=\"*\") filters results -- must be an asset name or a partial asset name followed by '*' ('*' matches all trailing characters)\n"
                "2. \"verbose\"                  (boolean, optional, default=false) when false results only contain balances -- when true results include outpoints\n"
                "3. \"count\"                    (integer, optional, default=ALL) truncates results to include only the first _count_ assets found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"
                "5. \"confs\"                    (integet, optional, default=0) results are skipped if they don't have this number of confirmations\n"

                "\nResult (verbose=false):\n"
                "{\n"
                "  (asset_name): balance,\n"
                "  ...\n"
                "}\n"

                "\nResult (verbose=true):\n"
                "{\n"
                "  (asset_name):\n"
                "    {\n"
                "      \"balance\": balance,\n"
                "      \"outpoints\":\n"
                "        [\n"
                "          {\n"
                "            \"txid\": txid,\n"
                "            \"vout\": vout,\n"
                "            \"amount\": amount\n"
                "          }\n"
                "          {...}, {...}\n"
                "        ]\n"
                "    }\n"
                "}\n"
                "{...}, {...}\n"

                "\nExamples:\n"
                + HelpExampleRpc("listmyassets", "")
                + HelpExampleCli("listmyassets", "ASSET")
                + HelpExampleCli("listmyassets", "\"ASSET*\" true 10 20")
                  + HelpExampleCli("listmyassets", "\"ASSET*\" true 10 20 1")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    std::string filter = "*";
    if (request.params.size() > 0)
        filter = request.params[0].get_str();

    if (filter == "")
        filter = "*";

    bool verbose = false;
    if (request.params.size() > 1)
        verbose = request.params[1].get_bool();

    size_t count = INT_MAX;
    if (request.params.size() > 2) {
        if (request.params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = request.params[2].get_int();
    }

    long start = 0;
    if (request.params.size() > 3) {
        start = request.params[3].get_int();
    }

    int confs = 0;
    if (request.params.size() > 4) {
        confs = request.params[4].get_int();
    }

    // retrieve balances
    std::map<std::string, CAmount> balances;
    std::map<std::string, std::vector<COutput> > outputs;
    if (filter == "*") {
        if (!GetAllMyAssetBalances(outputs, balances, confs))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset balances. For all assets");
    }
    else if (filter.back() == '*') {
        std::vector<std::string> assetNames;
        filter.pop_back();
        if (!GetAllMyAssetBalances(outputs, balances, confs, filter))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset balances. For all assets");
    }
    else {
        if (!IsAssetNameValid(filter))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset name.");
        if (!GetAllMyAssetBalances(outputs, balances, confs, filter))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset balances. For all assets");
    }

    // pagination setup
    auto bal = balances.begin();
    if (start >= 0)
        safe_advance(bal, balances.end(), (size_t)start);
    else
        safe_advance(bal, balances.end(), balances.size() + start);
    auto end = bal;
    safe_advance(end, balances.end(), count);

    // generate output
    UniValue result(UniValue::VOBJ);
    if (verbose) {
        for (; bal != end && bal != balances.end(); bal++) {
            UniValue asset(UniValue::VOBJ);
            asset.push_back(Pair("balance", UnitValueFromAmount(bal->second, bal->first)));

            UniValue outpoints(UniValue::VARR);
            for (auto const& out : outputs.at(bal->first)) {
                UniValue tempOut(UniValue::VOBJ);
                tempOut.push_back(Pair("txid", out.tx->GetHash().GetHex()));
                tempOut.push_back(Pair("vout", (int)out.i));

                //
                // get amount for this outpoint
                CAmount txAmount = 0;
                auto it = pwallet->mapWallet.find(out.tx->GetHash());
                if (it == pwallet->mapWallet.end()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
                }
                const CWalletTx* wtx = out.tx;
                CTxOut txOut = wtx->tx->vout[out.i];
                std::string strAddress;
                if (CheckIssueDataTx(txOut)) {
                    CNewAsset asset;
                    if (!AssetFromScript(txOut.scriptPubKey, asset, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = asset.nAmount;
                }
                else if (CheckReissueDataTx(txOut)) {
                    CReissueAsset asset;
                    if (!ReissueAssetFromScript(txOut.scriptPubKey, asset, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = asset.nAmount;
                }
                else if (CheckTransferOwnerTx(txOut)) {
                    CAssetTransfer asset;
                    if (!TransferAssetFromScript(txOut.scriptPubKey, asset, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = asset.nAmount;
                }
                else if (CheckOwnerDataTx(txOut)) {
                    std::string assetName;
                    if (!OwnerAssetFromScript(txOut.scriptPubKey, assetName, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = OWNER_ASSET_AMOUNT;
                }
                tempOut.push_back(Pair("amount", UnitValueFromAmount(txAmount, bal->first)));
                //
                //

                outpoints.push_back(tempOut);
            }
            asset.push_back(Pair("outpoints", outpoints));
            result.push_back(Pair(bal->first, asset));
        }
    }
    else {
        for (; bal != end && bal != balances.end(); bal++) {
            result.push_back(Pair(bal->first, UnitValueFromAmount(bal->second, bal->first)));
        }
    }
    return result;
}

#endif

UniValue listaddressesbyasset(const JSONRPCRequest &request)
{
    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    if (request.fHelp || !AreAssetsDeployed() || request.params.size() > 4 || request.params.size() < 1)
        throw std::runtime_error(
                "listaddressesbyasset \"asset_name\" (onlytotal) (count) (start)\n"
                + AssetActivationWarning() +
                "\nReturns a list of all address that own the given asset (with balances)"
                "\nOr returns the total size of how many address own the given asset"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset\n"
                "2. \"onlytotal\"                (boolean, optional, default=false) when false result is just a list of addresses with balances -- when true the result is just a single number representing the number of addresses\n"
                "3. \"count\"                    (integer, optional, default=50000, MAX=50000) truncates results to include only the first _count_ assets found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"

                "\nResult:\n"
                "[ "
                "  (address): balance,\n"
                "  ...\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listaddressesbyasset", "\"ASSET_NAME\" false 2 0")
                + HelpExampleCli("listaddressesbyasset", "\"ASSET_NAME\" true")
                + HelpExampleCli("listaddressesbyasset", "\"ASSET_NAME\"")
        );

    LOCK(cs_main);

    std::string asset_name = request.params[0].get_str();
    bool fOnlyTotal = false;
    if (request.params.size() > 1)
        fOnlyTotal = request.params[1].get_bool();

    size_t count = INT_MAX;
    if (request.params.size() > 2) {
        if (request.params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = request.params[2].get_int();
    }

    long start = 0;
    if (request.params.size() > 3) {
        start = request.params[3].get_int();
    }

    if (!IsAssetNameValid(asset_name))
        return "_Not a valid asset name";

    LOCK(cs_main);
    std::vector<std::pair<std::string, CAmount> > vecAddressAmounts;
    int nTotalEntries = 0;
    if (!passetsdb->AssetAddressDir(vecAddressAmounts, nTotalEntries, fOnlyTotal, asset_name, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve address asset directory.");

    // If only the number of addresses is wanted return it
    if (fOnlyTotal) {
        return nTotalEntries;
    }

    UniValue result(UniValue::VOBJ);
    for (auto& pair : vecAddressAmounts) {
        result.push_back(Pair(pair.first, UnitValueFromAmount(pair.second, asset_name)));
    }


    return result;
}
#ifdef ENABLE_WALLET

UniValue transfer(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 3 || request.params.size() > 7)
        throw std::runtime_error(
                "transfer \"asset_name\" qty \"to_address\" \"message\" expire_time \"change_address\" \"asset_change_address\"\n"
                + AssetActivationWarning() +
                "\nTransfers a quantity of an owned asset to a given address"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset\n"
                "2. \"qty\"                      (numeric, required) number of assets you want to send to the address\n"
                "3. \"to_address\"               (string, required) address to send the asset to\n"
                "4. \"message\"                  (string, optional) Once RIP5 is voted in ipfs hash or txid hash to send along with the transfer\n"
                "5. \"expire_time\"              (numeric, optional) UTC timestamp of when the message expires\n"
                "6. \"change_address\"       (string, optional, default = \"\") the transactions EVR change will be sent to this address\n"
                "7. \"asset_change_address\"     (string, optional, default = \"\") the transactions Asset change will be sent to this address\n"

                "\nResult:\n"
                "txid"
                "[ \n"
                "txid\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("transfer", "\"ASSET_NAME\" 20 \"address\" \"\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 15863654")
                + HelpExampleCli("transfer", "\"ASSET_NAME\" 20 \"address\" \"\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 15863654")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();

    if (IsAssetNameAQualifier(asset_name))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Please use the rpc call transferqualifierasset to send qualifier assets from this wallet.");

    CAmount nAmount = AmountFromValue(request.params[1]);

    std::string to_address = request.params[2].get_str();
    CTxDestination to_dest = DecodeDestination(to_address);
    if (!IsValidDestination(to_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + to_address);
    }

    bool fMessageCheck = false;
    std::string message = "";
    if (request.params.size() > 3) {
        message = request.params[3].get_str();
        if (!message.empty())
            fMessageCheck = true;
    }

    int64_t expireTime = 0;
    if (!message.empty()) {
        if (request.params.size() > 4) {
            expireTime = request.params[4].get_int64();
        }
    }

    if (!message.empty() || expireTime > 0) {
        if (!AreMessagesDeployed()) {
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Unable to send messages until Messaging RIP5 is enabled"));
        }
    }

    if (fMessageCheck)
        CheckIPFSTxidMessage(message, expireTime);

    std::string evr_change_address = "";
    if (request.params.size() > 5) {
        evr_change_address = request.params[5].get_str();
    }

    std::string asset_change_address = "";
    if (request.params.size() > 6) {
        asset_change_address = request.params[6].get_str();
    }

    CTxDestination evr_change_dest = DecodeDestination(evr_change_address);
    if (!evr_change_address.empty() && !IsValidDestination(evr_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("EVR change address must be a valid address. Invalid address: ") + evr_change_address);

    CTxDestination asset_change_dest = DecodeDestination(asset_change_address);
    if (!asset_change_address.empty() && !IsValidDestination(asset_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Asset change address must be a valid address. Invalid address: ") + asset_change_address);

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    CAssetTransfer transfer(asset_name, nAmount, DecodeAssetData(message), expireTime);

    vTransfers.emplace_back(std::make_pair(transfer, to_address));
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    ctrl.destChange = evr_change_dest;
    ctrl.assetDestChange = asset_change_dest;

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Do a validity check before commiting the transaction
    CheckRestrictedAssetTransferInputs(transaction, asset_name);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue transferfromaddresses(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 4 || request.params.size() > 8)
        throw std::runtime_error(
            "transferfromaddresses \"asset_name\" [\"from_addresses\"] qty \"to_address\" \"message\" expire_time \"evr_change_address\" \"asset_change_address\"\n"
            + AssetActivationWarning() +
            "\nTransfer a quantity of an owned asset in specific address(es) to a given address"

            "\nArguments:\n"
            "1. \"asset_name\"               (string, required) name of asset\n"
            "2. \"from_addresses\"           (array, required) list of from addresses to send from\n"
            "3. \"qty\"                      (numeric, required) number of assets you want to send to the address\n"
            "4. \"to_address\"               (string, required) address to send the asset to\n"
            "5. \"message\"                  (string, optional) Once RIP5 is voted in ipfs hash or txid hash to send along with the transfer\n"
            "6. \"expire_time\"              (numeric, optional) UTC timestamp of when the message expires\n"
            "7. \"evr_change_address\"       (string, optional, default = \"\") the transactions EVR change will be sent to this address\n"
            "8. \"asset_change_address\"     (string, optional, default = \"\") the transactions Asset change will be sent to this address\n"

            "\nResult:\n"
            "txid"
            "[ \n"
                "txid\n"
                "]\n"

            "\nExamples:\n"
            + HelpExampleCli("transferfromaddresses", "\"ASSET_NAME\" \'[\"fromaddress1\", \"fromaddress2\"]\' 20 \"to_address\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 154652365")
            + HelpExampleRpc("transferfromaddresses", "\"ASSET_NAME\" \'[\"fromaddress1\", \"fromaddress2\"]\' 20 \"to_address\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 154652365")
            );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();

    const UniValue& from_addresses = request.params[1];

    if (!from_addresses.isArray() || from_addresses.size() < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("From addresses must be a non-empty array."));
    }

    std::set<std::string> setFromDestinations;

    // Add the given array of addresses into the set of destinations
    for (int i = 0; i < (int) from_addresses.size(); i++) {
        std::string address = from_addresses[i].get_str();
        CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest))
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("From addresses must be valid addresses. Invalid address: ") + address);

        setFromDestinations.insert(address);
    }

    CAmount nAmount = AmountFromValue(request.params[2]);

    std::string address = request.params[3].get_str();

    bool fMessageCheck = false;
    std::string message = "";
    if (request.params.size() > 4) {
        message = request.params[4].get_str();
        if (!message.empty())
            fMessageCheck = true;
    }

    int64_t expireTime = 0;
    if (!message.empty()) {
        if (request.params.size() > 5) {
            expireTime = request.params[5].get_int64();
        }
    }

    if (fMessageCheck)
        CheckIPFSTxidMessage(message, expireTime);

    std::string evr_change_address = "";
    if (request.params.size() > 6) {
        evr_change_address = request.params[6].get_str();
    }

    std::string asset_change_address = "";
    if (request.params.size() > 7) {
        asset_change_address = request.params[7].get_str();
    }

    CTxDestination evr_change_dest = DecodeDestination(evr_change_address);
    if (!evr_change_address.empty() && !IsValidDestination(evr_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("EVR change address must be a valid address. Invalid address: ") + evr_change_address);

    CTxDestination asset_change_dest = DecodeDestination(asset_change_address);
    if (!asset_change_address.empty() && !IsValidDestination(asset_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Asset change address must be a valid address. Invalid address: ") + asset_change_address);

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    vTransfers.emplace_back(std::make_pair(CAssetTransfer(asset_name, nAmount, DecodeAssetData(message), expireTime), address));
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    std::map<std::string, std::vector<COutput> > mapAssetCoins;
    pwallet->AvailableAssets(mapAssetCoins);

    // Set the change addresses
    ctrl.destChange = evr_change_dest;
    ctrl.assetDestChange = asset_change_dest;

    if (!mapAssetCoins.count(asset_name)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Wallet doesn't own the asset_name: " + asset_name));
    }

    // Add all the asset outpoints that match the set of given from addresses
    for (const auto& out : mapAssetCoins.at(asset_name)) {
        // Get the address that the coin resides in, because to send a valid message. You need to send it to the same address that it currently resides in.
        CTxDestination dest;
        ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest);

        if (setFromDestinations.count(EncodeDestination(dest)))
            ctrl.SelectAsset(COutPoint(out.tx->GetHash(), out.i));
    }

    std::vector<COutPoint> outs;
    ctrl.ListSelectedAssets(outs);
    if (!outs.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("No asset outpoints are selected from the given addresses, failed to create the transaction"));
    }

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee))
    throw JSONRPCError(error.first, error.second);

    // Do a validity check before commiting the transaction
    CheckRestrictedAssetTransferInputs(transaction, asset_name);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
    throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue transferfromaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 4 || request.params.size() > 8)
        throw std::runtime_error(
                "transferfromaddress \"asset_name\" \"from_address\" qty \"to_address\" \"message\" expire_time \"evr_change_address\" \"asset_change_address\"\n"
                + AssetActivationWarning() +
                "\nTransfer a quantity of an owned asset in a specific address to a given address"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset\n"
                "2. \"from_address\"             (string, required) address that the asset will be transferred from\n"
                "3. \"qty\"                      (numeric, required) number of assets you want to send to the address\n"
                "4. \"to_address\"               (string, required) address to send the asset to\n"
                "5. \"message\"                  (string, optional) Once RIP5 is voted in ipfs hash or txid hash to send along with the transfer\n"
                "6. \"expire_time\"              (numeric, optional) UTC timestamp of when the message expires\n"
                "7. \"evr_change_address\"       (string, optional, default = \"\") the transaction EVR change will be sent to this address\n"
                "8. \"asset_change_address\"     (string, optional, default = \"\") the transaction Asset change will be sent to this address\n"

                "\nResult:\n"
                "txid"
                "[ \n"
                "txid\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("transferfromaddress", "\"ASSET_NAME\" \"fromaddress\" 20 \"address\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\", 156545652")
                + HelpExampleRpc("transferfromaddress", "\"ASSET_NAME\" \"fromaddress\" 20 \"address\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\", 156545652")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();

    std::string from_address = request.params[1].get_str();

    // Check to make sure the given from address is valid
    CTxDestination dest = DecodeDestination(from_address);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("From address must be valid addresses. Invalid address: ") + from_address);

    CAmount nAmount = AmountFromValue(request.params[2]);

    std::string address = request.params[3].get_str();


    bool fMessageCheck = false;
    std::string message = "";
    if (request.params.size() > 4) {

        message = request.params[4].get_str();
        if (!message.empty())
            fMessageCheck = true;
    }

    int64_t expireTime = 0;
    if (!message.empty()) {
        if (request.params.size() > 5) {
            expireTime = request.params[5].get_int64();
        }
    }

    if (fMessageCheck)
        CheckIPFSTxidMessage(message, expireTime);

    std::string evr_change_address = "";
    if (request.params.size() > 6) {
        evr_change_address = request.params[6].get_str();
    }

    std::string asset_change_address = "";
    if (request.params.size() > 7) {
        asset_change_address = request.params[7].get_str();
    }

    CTxDestination evr_change_dest = DecodeDestination(evr_change_address);
    if (!evr_change_address.empty() && !IsValidDestination(evr_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("EVR change address must be a valid address. Invalid address: ") + evr_change_address);

    CTxDestination asset_change_dest = DecodeDestination(asset_change_address);
    if (!asset_change_address.empty() && !IsValidDestination(asset_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Asset change address must be a valid address. Invalid address: ") + asset_change_address);


    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    vTransfers.emplace_back(std::make_pair(CAssetTransfer(asset_name, nAmount, DecodeAssetData(message), expireTime), address));
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    std::map<std::string, std::vector<COutput> > mapAssetCoins;
    pwallet->AvailableAssets(mapAssetCoins);

    // Set the change addresses
    ctrl.destChange = evr_change_dest;
    ctrl.assetDestChange = asset_change_dest;

    if (!mapAssetCoins.count(asset_name)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Wallet doesn't own the asset_name: " + asset_name));
    }

    // Add all the asset outpoints that match the given from addresses
    for (const auto& out : mapAssetCoins.at(asset_name)) {
        // Get the address that the coin resides in, because to send a valid message. You need to send it to the same address that it currently resides in.
        CTxDestination dest;
        ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest);

        if (from_address == EncodeDestination(dest))
            ctrl.SelectAsset(COutPoint(out.tx->GetHash(), out.i));
    }

    std::vector<COutPoint> outs;
    ctrl.ListSelectedAssets(outs);
    if (!outs.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("No asset outpoints are selected from the given address, failed to create the transaction"));
    }

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Do a validity check before commiting the transaction
    CheckRestrictedAssetTransferInputs(transaction, asset_name);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}


UniValue reissue(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() > 13 || request.params.size() < 3)
        throw std::runtime_error(
            "reissue \"asset_name\" qty \"to_address\" \"change_address\" ( reissuable ) ( new_units) \"( new_ipfs )\" \"( permanent_ipfs )\" ( change_toll_amount ) ( toll_amount ) \"( toll_address ) ( toll_amount_mutability ) ( toll_address_mutability )\"\n"
            + AssetActivationWarning() +
            "\nReissues a quantity of an asset to an owned address if you own the Owner Token"
            "\nCan change the reissuable flag during reissuance"
            "\nCan change the IPFS hash during reissuance"
            "\nCan specify optional toll asset details."

            "\nArguments:\n"
            "1. \"asset_name\"               (string, required) name of the asset that is being reissued\n"
            "2. \"qty\"                      (numeric, required) number of assets to reissue\n"
            "3. \"to_address\"               (string, required) address to send the asset to\n"
            "4. \"change_address\"           (string, optional) address that the change of the transaction will be sent to\n"
            "5. \"reissuable\"               (boolean, optional, default=true), whether future reissuance is allowed\n"
            "6. \"new_units\"                (numeric, optional, default=-1), the new units that will be associated with the asset\n"
            "7. \"new_ipfs\"                 (string, optional, default=\"\"), whether to update the current IPFS hash or txid once RIP5 is active\n"
            "8. \"new_permanent_ipfs\"          (string, optional, default=\"\"), a new permanent IPFS hash\n"
            "9. \"change_toll_amount\"        (boolean, optional, default=false), whether the toll amount is being changed\n"
            "10. \"new_toll_amount\"             (numeric, optional, default=0), the toll amount to be associated with the asset\n"
            "11. \"new_toll_address\"            (string, optional, default=\"\"), the toll address to be associated with the asset\n"
            "12. \"toll_amount_mutability\"      (boolean, optional, default=true), whether future changing is allowed on toll amount\n"
            "13. \"toll_address_mutability\"      (boolean, optional, default=true), whether future changing is allowed on toll address\n"

            "\nResult:\n"
            "\"txid\"                     (string) The transaction id\n"

            "\nExamples:\n"
            + HelpExampleCli("reissue", "\"ASSET_NAME\" 20 \"address\"")
            + HelpExampleRpc("reissue", "\"ASSET_NAME\" 20 \"address\" \"change_address\" \"true\" 8 \"Qmd286K6pohQcTKYqnS1YhWrCiS4gz7Xi34sdwMe9USZ7u\" \"Qmd286K6pohQcTKYqnS1YhWrCiS4gz7Xi34sdwMe9USZ7u\" true 100 \"toll_address\" true true")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();
    CAmount nAmount = AmountFromValue(request.params[1]);
    std::string address = request.params[2].get_str();

    std::string changeAddress = "";
    if (request.params.size() > 3)
        changeAddress = request.params[3].get_str();

    if (!changeAddress.empty()) {
        CTxDestination destination = DecodeDestination(changeAddress);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Change Address: Invalid Evrmore address: ") + changeAddress);
        }
    }

    bool reissuable = true;
    if (request.params.size() > 4)
        reissuable = request.params[4].get_bool();

    int newUnits = -1;
    if (request.params.size() > 5)
        newUnits = request.params[5].get_int();

    std::string newipfs = "";
    bool fMessageCheck = false;
    if (request.params.size() > 6) {
        newipfs = request.params[6].get_str();
        if (newipfs.size() > 0)
            fMessageCheck = true;
    }

    // New field: permanent IPFS hash
    bool fCheckPermanent = false;
    std::string newPermanentIPFSHash = "";
    if (request.params.size() > 7) {
        newPermanentIPFSHash = request.params[7].get_str();
        if (newPermanentIPFSHash.size() > 0)
            fCheckPermanent = true;
    }

    // New field: fChangeTollAmount
    bool fChangeTollAmount = false;
    if (request.params.size() > 8) {
        fChangeTollAmount = request.params[8].get_bool();
    }

    // New field: toll amount
    CAmount newTollAmount = 0;
    if (request.params.size() > 9) {
        newTollAmount = AmountFromValue(request.params[9]);
    }

    // New field: toll address
    std::string newTollAddress = "";
    if (request.params.size() > 10) {
        newTollAddress = request.params[10].get_str();
        if (!newTollAddress.empty()) {
            CTxDestination destination = DecodeDestination(newTollAddress);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Toll Address: Invalid Evrmore address: ") + newTollAddress);
            }
        }
    }

    // New field: fTollAmountMutable
    bool fTollAmountMutable = true;
    if (request.params.size() > 11) {
        fTollAmountMutable = request.params[11].get_bool();
    }

    // New field: fTollAddressReissuable
    bool fTollAddressMutable = true;
    if (request.params.size() > 12) {
        fTollAddressMutable = request.params[12].get_bool();
    }

    int64_t expireTime = 0;
    if (fMessageCheck)
        CheckIPFSTxidMessage(newipfs, expireTime);

    if (fCheckPermanent)
        CheckIPFSTxidMessage(newPermanentIPFSHash, expireTime);

    // Reissuing rpc call can't be used to remint
    // Use remint rpccall
    bool reminting_asset = false;

    // Don't change this value if it is already true
    bool remintable = true;

    // Create a CReissueAsset object with all parameters
    CReissueAsset reissueAsset(asset_name, nAmount, newUnits, reissuable, DecodeAssetData(newipfs), DecodeAssetData(newPermanentIPFSHash), fChangeTollAmount, newTollAmount, newTollAddress, reminting_asset, fTollAmountMutable, fTollAddressMutable, remintable);

    std::pair<int, std::string> error;
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(changeAddress);

    LogPrintf("Creating reissue transaction with hashses: --%s--, --%s--\n", newipfs, newPermanentIPFSHash);
    // Create the Transaction
    if (!CreateReissueAssetTransaction(pwallet, crtl, reissueAsset, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    std::string strError = "";
    if (!ContextualCheckReissueAsset(passets, reissueAsset, strError, *transaction.tx.get()))
        throw JSONRPCError(RPC_INVALID_REQUEST, strError);

    LogPrintf("0 Setting the reissue flags to Amount: %d, Address: %d\n", reissueAsset.nTollAmountMutability, reissueAsset.nTollAddressMutability);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue updatemetadata(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || !IsTollsActive() || request.params.size() > 9 || request.params.size() < 3)
    throw std::runtime_error(
        "updatemetadata \"asset_name\" \"change_address\" \"ipfs_hash\" \"permanent_ipfs\" \"toll_address\" ( change_toll_amount ) ( toll_amount ) ( toll_amount_mutability ) ( toll_address_mutability )\n"
        + AssetActivationWarning() +
        "\nUpdates the metadata of an asset. Requires the owner token of the asset."
        "\nCan modify toll details, IPFS hash, and other metadata during the update."

        "\nArguments:\n"
        "1. \"asset_name\"               (string, required) The name of the asset being updated.\n"
        "2. \"change_address\"           (string, optional) The address where the change should be sent to.\n"
        "3. \"ipfs_hash\"                (string, optional) The new IPFS hash for the asset (default=\"\").\n"
        "4. \"permanent_ipfs\"           (string, optional) The new permanent IPFS hash for the asset. Once this is set. It can't be changed (default=\"\").\n"
        "5. \"toll_address\"             (string, optional) The address to collect toll fees for asset transactions (default=\"\").\n"
        "6. \"change_toll_amount\"       (boolean, optional, default=False) Whether to modify the toll amount.\n"
        "7. \"toll_amount\"              (numeric, optional, default=-1) The new toll amount for the asset.\n"
        "8. \"toll_amount_mutability\"   (boolean, optional, default=True) Whether the toll amount can be modified in the future.\n"
        "9. \"toll_address_mutability\"  (boolean, optional, default=True) Whether the toll address can be modified in the future.\n"

        "\nResult:\n"
        "\"txid\"                        (string) The transaction ID of the update.\n"

        "\nExamples:\n"
        + HelpExampleCli("updatemetadata", "\"ASSET_NAME\" \"\" \"Qmd286K6pohQcTKYqnS1YhWrCiS4gz7Xi34sdwMe9USZ7u\" \"QmeYfp9kVxrQo92EMpNzBrAtwxPQzqLZ9sQDL6pZ6Ffdr5\" \"toll_address\" true 10 true false")
        + HelpExampleRpc("updatemetadata", "\"ASSET_NAME\", \"\", \"Qmd286K6pohQcTKYqnS1YhWrCiS4gz7Xi34sdwMe9USZ7u\", \"QmeYfp9kVxrQo92EMpNzBrAtwxPQzqLZ9sQDL6pZ6Ffdr5\", \"toll_address\", true, 10, true, false")
    );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);


    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();
    std::string changeAddress = "";
    if (request.params.size() > 1)
        changeAddress = request.params[1].get_str();

    if (!changeAddress.empty()) {
        CTxDestination destination = DecodeDestination(changeAddress);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Change Address: Invalid Evrmore address: ") + changeAddress);
        }
    }

    std::string newipfs = "";
    bool fCheckIPFSHash = false;
    if (request.params.size() > 2) {
        newipfs = request.params[2].get_str();
        if (newipfs.size() > 0)
            fCheckIPFSHash = true;
    }

    bool fCheckPermanentIPFSHash = false;
    std::string newpermanentipfshash = "";
    if (request.params.size() > 3) {
        newpermanentipfshash = request.params[3].get_str();
        if (newpermanentipfshash.size() > 0)
            fCheckPermanentIPFSHash = true;
    }

    std::string newTollAddress = "";
    if (request.params.size() > 4) {
        newTollAddress = request.params[4].get_str();
        if (!newTollAddress.empty()) {
            CTxDestination destination = DecodeDestination(newTollAddress);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Toll Address: Invalid Evrmore address: ") + newTollAddress);
            }
        }
    }

    bool fChangeTollAmount = false;
    if (request.params.size() > 5) {
        fChangeTollAmount = request.params[5].get_bool();
    }

    CAmount newTollAmount = 0;
    if (request.params.size() > 6) {
        newTollAmount = AmountFromValue(request.params[6]);
    }

    bool fTollAmountMutability = true;
    if (request.params.size() > 7) {
        fTollAmountMutability = request.params[7].get_bool();
    }

    bool fTollAddressMutability = true;
    if (request.params.size() > 8) {
        fTollAddressMutability = request.params[8].get_bool();
    }

    int64_t expireTime = 0;
    if (fCheckIPFSHash)
        CheckIPFSTxidMessage(newipfs, expireTime);

    if (fCheckPermanentIPFSHash)
        CheckIPFSTxidMessage(newpermanentipfshash, expireTime);

    // Default reissue parameters.
    CAmount nAmount = 0;
    int nUnits = -1;
    bool fReissuable = true;

    // We need a valid address, but because we aren't issuing any assets. We can use the burn address.
    std::string address = GetParams().ReissueAssetBurnAddress();

    // updatemetadata rpc call can't be used to remint
    // Use remint rpccall
    bool reminting_asset = false;

    // Don't change this value if it is already true
    bool remintable = true;

    // Create a CReissueAsset object with all parameters that only change the metadata
    CReissueAsset reissueAsset(asset_name, nAmount, nUnits, fReissuable, DecodeAssetData(newipfs), DecodeAssetData(newpermanentipfshash), fChangeTollAmount, newTollAmount, newTollAddress, reminting_asset, fTollAmountMutability, fTollAddressMutability, remintable);

    std::pair<int, std::string> error;
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(changeAddress);

    LogPrintf("Creating updatemetadata transaction with hashses: --%s--, --%s--\n", newipfs, newpermanentipfshash);
    // Create the Transaction
    if (!CreateReissueAssetTransaction(pwallet, crtl, reissueAsset, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    std::string strError = "";
    if (!ContextualCheckReissueAsset(passets, reissueAsset, strError, *transaction.tx.get()))
        throw JSONRPCError(RPC_INVALID_REQUEST, strError);

    LogPrintf("0 Setting the mutability flags to Amount: %d, Address: %d\n", reissueAsset.nTollAmountMutability, reissueAsset.nTollAddressMutability);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue remint(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || !IsTollsActive() || request.params.size() > 5 || request.params.size() < 3)
    throw std::runtime_error(
        "remint \"asset_name\" \"qty\" \"to_address\" \"change_address\" \"update_remintable\"\n"
        + AssetActivationWarning() +
        "\nRemints an asset that has been burned. Requires the owner token of the asset."
        "\nCan disable remintable also in needed"

        "\nArguments:\n"
        "1. \"asset_name\"               (string, required) The name of the asset being updated.\n"
        "2. \"qty\"                      (numeric, required) number of assets to remint\n"
        "3. \"to_address\"               (string, required) address that the reminted assets to go to\n"
        "4. \"change_address\"           (string, optional) The address where the change should be sent to.\n"
        "5. \"update_remintable\"        (boolean, optional default=true) If we are disabling reminting option for this asset \n"


        "\nResult:\n"
        "\"txid\"                        (string) The transaction ID of the update.\n"

        "\nExamples:\n"
        + HelpExampleCli("remint", "\"ASSET_NAME\" 10 \"to_address\" \"change_Address\" true")
        + HelpExampleRpc("remint", "\"ASSET_NAME\", 10, \"to_address\", \"change_Address\", true")
    );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();
    CAmount amount = AmountFromValue(request.params[1]);
    std::string to_address = request.params[2].get_str();

    std::string change_address = "";
    if (request.params.size() > 3)
        change_address = request.params[3].get_str();

    bool remintable = true;
    if (request.params.size() > 4) {
        remintable = request.params[4].get_bool();
    }

    CTxDestination destination = DecodeDestination(to_address);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid To Address: Invalid Evrmore address: ") + to_address);
    }


    if (!change_address.empty()) {
        CTxDestination destination = DecodeDestination(change_address);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Change Address: Invalid Evrmore address: ") + change_address);
        }
    }

    // Create a CReissueAsset for reminting
    CReissueAsset reissueAsset(asset_name, amount, remintable);

    std::pair<int, std::string> error;
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(change_address);

    LogPrintf("Creating reminting transaction. Asset Name : %s, Amount: %d, Address: %s, New Remintable Setting: %d\n", asset_name, amount, to_address, remintable);

    // Create the Transaction
    if (!CreateReissueAssetTransaction(pwallet, crtl, reissueAsset, to_address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    std::string strError = "";
    if (!ContextualCheckReissueAsset(passets, reissueAsset, strError, *transaction.tx.get()))
        throw JSONRPCError(RPC_INVALID_REQUEST, strError);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

#endif

UniValue getcalculatedtoll(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
                "getcalculatedtoll \"asset_name\" amount ( change_amount ) ( overwrite_toll_fee )\n"
                "\nCalculate the toll for transferring an asset.\n"
                "\nIf asset name is empty, and overwrite toll fee is not supplied. 0.1 will be the toll fee\n"
                "\nArguments:\n"
                "1. \"asset_name\"          (string, optional default = \"\") The name of the asset.\n"
                "2. amount                  (numeric, optional default = 100) The amount of the asset being sent.\n"
                "3. change_amount           (numeric, optional, default = 0) The amount sent back to the sender as change.\n"
                "4. overwrite_toll_fee      (numeric, optional) If provided, this value will be used as the toll fee.\n"
                "\nResult:\n"
                "\"asset_name\"           (string) The asset from which the toll fee and address are coming from\n"
                "\"toll_fee\"             (numeric) The fee being used for this calculation\n"
                "\"toll_address\"         (numeric) The toll address assigned to the given asset if asset exists\n"
                "\"amount_sending\"       (numeric) The amount of asset that is being sent minus the change\n"
                "\"est_calculated_toll\"  (numeric) The calculated toll fee for the transaction.\n"
                "\nExamples:\n"
                + HelpExampleCli("getcalculatedtoll", "\"ASSET_NAME\" 100 10 0.05")
                + HelpExampleRpc("getcalculatedtoll", "\"ASSET_NAME\", 100, 10, 0.05")
        );

    LOCK(cs_main);

    if (!IsTollsActive()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Tolls not active");
    }

    // Extract parameters
    std::string asset_name = request.params.size() > 0 && !request.params[0].isNull() ? request.params[0].get_str() : "";
    CAmount amount = request.params.size() > 1 && !request.params[1].isNull() ? AmountFromValue(request.params[1]) : 100 * COIN;
    CAmount change_amount = request.params.size() > 2 && !request.params[2].isNull() ? AmountFromValue(request.params[2]) : 0;

    std::string toll_address = "";
    CAmount toll_fee = 0;

    if (change_amount > amount) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "change_amount can't be bigger than amount");
    }

    if (amount == 0 || amount - change_amount == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "amount can't be zero. amount - change_amount can't be zero");
    }

    CNewAsset asset;
    if (!asset_name.empty()) {
        auto currentActiveAssetCache = GetCurrentAssetCache();
        if (currentActiveAssetCache) {
            if (currentActiveAssetCache->GetAssetMetaDataIfExists(asset_name, asset)) {
                toll_fee = asset.nTollAmount;
                toll_address = asset.strTollAddress;
            }
        }
    }

    if (asset_name.empty() && request.params.size() < 3) {
        toll_fee = 0.1 * COIN;
    }

    // overwrite the toll fee
    if (request.params.size() > 3) {
        toll_fee = AmountFromValue(request.params[3]);
    }

    if (asset_name != asset.strName) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "asset metadata can't be found. ");
    }

    CAmount calculated_toll = CalculateToll(amount - change_amount, toll_fee);

    UniValue result(UniValue::VOBJ);
    result.pushKV("asset_name", asset_name);
    result.pushKV("toll_fee", ValueFromAmount(toll_fee));
    result.pushKV("toll_address", toll_address);
    result.pushKV("amount_sending", ValueFromAmount(amount - change_amount));
    result.pushKV("est_calculated_toll", ValueFromAmount(calculated_toll));
    return result;
}

UniValue listassets(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() > 4)
        throw std::runtime_error(
                "listassets \"( asset )\" ( verbose ) ( count ) ( start )\n"
                + AssetActivationWarning() +
                "\nReturns a list of all assets\n"
                "\nThis could be a slow/expensive operation as it reads from the database\n"

                "\nArguments:\n"
                "1. \"asset\"                    (string, optional, default=\"*\") filters results -- must be an asset name or a partial asset name followed by '*' ('*' matches all trailing characters)\n"
                "2. \"verbose\"                  (boolean, optional, default=false) when false result is just a list of asset names -- when true results are asset name mapped to metadata\n"
                "3. \"count\"                    (integer, optional, default=ALL) truncates results to include only the first _count_ assets found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"

                "\nResult (verbose=false):\n"
                "[\n"
                "  asset_name,\n"
                "  ...\n"
                "]\n"

                "\nResult (verbose=true):\n"
                "{\n"
                "  (asset_name):\n"
                "    {\n"
                "      amount: (number),\n"
                "      units: (number),\n"
                "      reissuable: (number),\n"
                "      has_ipfs: (number),\n"
                "      ipfs_hash: (hash) (only if has_ipfs = 1 and data is a ipfs hash)\n"
                "      ipfs_hash: (hash) (only if has_ipfs = 1 and data is a txid hash)\n"
                "    },\n"
                "  {...}, {...}\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleRpc("listassets", "")
                + HelpExampleCli("listassets", "ASSET")
                + HelpExampleCli("listassets", "\"ASSET*\" true 10 20")
        );

    ObserveSafeMode();

    if (!passetsdb)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "asset db unavailable.");

    std::string filter = "*";
    if (request.params.size() > 0)
        filter = request.params[0].get_str();

    if (filter == "")
        filter = "*";

    bool verbose = false;
    if (request.params.size() > 1)
        verbose = request.params[1].get_bool();

    size_t count = INT_MAX;
    if (request.params.size() > 2) {
        if (request.params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = request.params[2].get_int();
    }

    long start = 0;
    if (request.params.size() > 3) {
        start = request.params[3].get_int();
    }

    std::vector<CDatabasedAssetData> assets;
    if (!passetsdb->AssetDir(assets, filter, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve asset directory.");

    UniValue result;
    result = verbose ? UniValue(UniValue::VOBJ) : UniValue(UniValue::VARR);

    for (auto data : assets) {
        CNewAsset asset = data.asset;
        if (verbose) {
            UniValue detail(UniValue::VOBJ);
            detail.push_back(Pair("block_height", data.nHeight));
            detail.push_back(Pair("blockhash", data.blockHash.GetHex()));
            assetToJSON(asset, detail);

            result.push_back(Pair(asset.strName, detail));
        } else {
            result.push_back(asset.strName);
        }
    }

    return result;
}

UniValue getcacheinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size())
        throw std::runtime_error(
                "getcacheinfo \n"
                + AssetActivationWarning() +

                "\nResult:\n"
                "[\n"
                "  uxto cache size:\n"
                "  asset total (exclude dirty):\n"
                "  asset address map:\n"
                "  asset address balance:\n"
                "  my unspent asset:\n"
                "  reissue data:\n"
                "  asset metadata map:\n"
                "  asset metadata list (est):\n"
                "  dirty cache (est):\n"


                "]\n"

                "\nExamples:\n"
                + HelpExampleRpc("getcacheinfo", "")
                + HelpExampleCli("getcacheinfo", "")
        );

    auto currentActiveAssetCache = GetCurrentAssetCache();
    if (!currentActiveAssetCache)
        throw JSONRPCError(RPC_VERIFY_ERROR, "asset cache is null");

    if (!pcoinsTip)
        throw JSONRPCError(RPC_VERIFY_ERROR, "coins tip cache is null");

    if (!passetsCache)
        throw JSONRPCError(RPC_VERIFY_ERROR, "asset metadata cache is nul");

    UniValue result(UniValue::VARR);

    UniValue info(UniValue::VOBJ);
    info.push_back(Pair("uxto cache size", (int)pcoinsTip->DynamicMemoryUsage()));
    info.push_back(Pair("asset total (exclude dirty)", (int)currentActiveAssetCache->DynamicMemoryUsage()));

    UniValue descendants(UniValue::VOBJ);

    descendants.push_back(Pair("asset address balance",   (int)memusage::DynamicUsage(currentActiveAssetCache->mapAssetsAddressAmount)));
    descendants.push_back(Pair("reissue data",   (int)memusage::DynamicUsage(currentActiveAssetCache->mapReissuedAssetData)));

    info.push_back(Pair("reissue tracking (memory only)", (int)memusage::DynamicUsage(mapReissuedAssets) + (int)memusage::DynamicUsage(mapReissuedTx)));
    info.push_back(Pair("asset data", descendants));
    info.push_back(Pair("asset metadata map",  (int)memusage::DynamicUsage(passetsCache->GetItemsMap())));
    info.push_back(Pair("asset metadata list (est)",  (int)passetsCache->GetItemsList().size() * (32 + 80))); // Max 32 bytes for asset name, 80 bytes max for asset data
    info.push_back(Pair("dirty cache (est)",  (int)currentActiveAssetCache->GetCacheSize()));
    info.push_back(Pair("dirty cache V2 (est)",  (int)currentActiveAssetCache->GetCacheSizeV2()));

    result.push_back(info);
    return result;
}

#ifdef ENABLE_WALLET
UniValue addtagtoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
                "addtagtoaddress tag_name to_address (change_address) (asset_data)\n"
                + RestrictedActivationWarning() +
                "\nAssign a tag to a address\n"

                "\nArguments:\n"
                "1. \"tag_name\"            (string, required) the name of the tag you are assigning to the address, if it doens't have '#' at the front it will be added\n"
                "2. \"to_address\"          (string, required) the address that will be assigned the tag\n"
                "3. \"change_address\"      (string, optional) The change address for the qualifier token to be sent to\n"
                "4. \"asset_data\"          (string, optional) The asset data (ipfs or a hash) to be applied to the transfer of the qualifier token\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("addtagtoaddress", "\"#TAG\" \"to_address\"")
                + HelpExampleRpc("addtagtoaddress", "\"#TAG\" \"to_address\"")
                + HelpExampleCli("addtagtoaddress", "\"#TAG\" \"to_address\" \"change_address\"")
                + HelpExampleRpc("addtagtoaddress", "\"#TAG\" \"to_address\" \"change_address\"")
        );

    // 1 - on
    return UpdateAddressTag(request, 1);
}

UniValue removetagfromaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
                "removetagfromaddress tag_name to_address (change_address) (asset_data)\n"
                + RestrictedActivationWarning() +
                "\nRemove a tag from a address\n"

                "\nArguments:\n"
                "1. \"tag_name\"            (string, required) the name of the tag you are removing from the address\n"
                "2. \"to_address\"          (string, required) the address that the tag will be removed from\n"
                "3. \"change_address\"      (string, optional) The change address for the qualifier token to be sent to\n"
                "4. \"asset_data\"          (string, optional) The asset data (ipfs or a hash) to be applied to the transfer of the qualifier token\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("removetagfromaddress", "\"#TAG\" \"to_address\"")
                + HelpExampleRpc("removetagfromaddress", "\"#TAG\" \"to_address\"")
                + HelpExampleCli("removetagfromaddress", "\"#TAG\" \"to_address\" \"change_address\"")
                + HelpExampleRpc("removetagfromaddress", "\"#TAG\" \"to_address\" \"change_address\"")
        );

    // 0 = off
    return UpdateAddressTag(request, 0);
}

UniValue freezeaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
                "freezeaddress asset_name address (change_address) (asset_data)\n"
                + RestrictedActivationWarning() +
                "\nFreeze an address from transferring a restricted asset\n"

                "\nArguments:\n"
                "1. \"asset_name\"       (string, required) the name of the restricted asset you want to freeze\n"
                "2. \"address\"          (string, required) the address that will be frozen\n"
                "3. \"change_address\"   (string, optional) The change address for the owner token of the restricted asset\n"
                "4. \"asset_data\"       (string, optional) The asset data (ipfs or a hash) to be applied to the transfer of the owner token\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("freezeaddress", "\"$RESTRICTED_ASSET\" \"address\"")
                + HelpExampleRpc("freezeaddress", "\"$RESTRICTED_ASSET\" \"address\"")
                + HelpExampleCli("freezeaddress", "\"$RESTRICTED_ASSET\" \"address\" \"change_address\"")
                + HelpExampleRpc("freezeaddress", "\"$RESTRICTED_ASSET\" \"address\" \"change_address\"")
        );

    // 1 = Freeze
    return UpdateAddressRestriction(request, 1);
}

UniValue unfreezeaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
                "unfreezeaddress asset_name address (change_address) (asset_data)\n"
                + RestrictedActivationWarning() +
                "\nUnfreeze an address from transferring a restricted asset\n"

                "\nArguments:\n"
                "1. \"asset_name\"       (string, required) the name of the restricted asset you want to unfreeze\n"
                "2. \"address\"          (string, required) the address that will be unfrozen\n"
                "3. \"change_address\"   (string, optional) The change address for the owner token of the restricted asset\n"
                "4. \"asset_data\"       (string, optional) The asset data (ipfs or a hash) to be applied to the transfer of the owner token\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("unfreezeaddress", "\"$RESTRICTED_ASSET\" \"address\"")
                + HelpExampleRpc("unfreezeaddress", "\"$RESTRICTED_ASSET\" \"address\"")
                + HelpExampleCli("unfreezeaddress", "\"$RESTRICTED_ASSET\" \"address\" \"change_address\"")
                + HelpExampleRpc("unfreezeaddress", "\"$RESTRICTED_ASSET\" \"address\" \"change_address\"")
        );

    // 0 = Unfreeze
    return UpdateAddressRestriction(request, 0);
}

UniValue freezerestrictedasset(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                "freezerestrictedasset asset_name (change_address) (asset_data)\n"
                + RestrictedActivationWarning() +
                "\nFreeze all trading for a specific restricted asset\n"

                "\nArguments:\n"
                "1. \"asset_name\"       (string, required) the name of the restricted asset you want to unfreeze\n"
                "2. \"change_address\"   (string, optional) The change address for the owner token of the restricted asset\n"
                "3. \"asset_data\"       (string, optional) The asset data (ipfs or a hash) to be applied to the transfer of the owner token\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("freezerestrictedasset", "\"$RESTRICTED_ASSET\"")
                + HelpExampleRpc("freezerestrictedasset", "\"$RESTRICTED_ASSET\"")
                + HelpExampleCli("freezerestrictedasset", "\"$RESTRICTED_ASSET\" \"change_address\"")
                + HelpExampleRpc("freezerestrictedasset", "\"$RESTRICTED_ASSET\" \"change_address\"")
        );

    // 1 = Freeze all trading
    return UpdateGlobalRestrictedAsset(request, 1);
}

UniValue unfreezerestrictedasset(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                "unfreezerestrictedasset asset_name (change_address) (asset_data)\n"
                + RestrictedActivationWarning() +
                "\nUnfreeze all trading for a specific restricted asset\n"

                "\nArguments:\n"
                "1. \"asset_name\"       (string, required) the name of the restricted asset you want to unfreeze\n"
                "2. \"change_address\"   (string, optional) The change address for the owner token of the restricted asset\n"
                "4. \"asset_data\"       (string, optional) The asset data (ipfs or a hash) to be applied to the transfer of the owner token\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("unfreezerestrictedasset", "\"$RESTRICTED_ASSET\"")
                + HelpExampleRpc("unfreezerestrictedasset", "\"$RESTRICTED_ASSET\"")
                + HelpExampleCli("unfreezerestrictedasset", "\"$RESTRICTED_ASSET\" \"change_address\"")
                + HelpExampleRpc("unfreezerestrictedasset", "\"$RESTRICTED_ASSET\" \"change_address\"")
        );

    // 0 = Unfreeze all trading
    return UpdateGlobalRestrictedAsset(request, 0);
}
#endif

UniValue listtagsforaddress(const JSONRPCRequest &request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() !=1)
        throw std::runtime_error(
                "listtagsforaddress address\n"
                + RestrictedActivationWarning() +
                "\nList all tags assigned to an address\n"

                "\nArguments:\n"
                "1. \"address\"          (string, required) the address to list tags for\n"

                "\nResult:\n"
                "["
                "\"tag_name\",        (string) The tag name\n"
                "...,\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listtagsforaddress", "\"address\"")
                + HelpExampleRpc("listtagsforaddress", "\"address\"")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    std::string address = request.params[0].get_str();

    // Check to make sure the given from address is valid
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Not valid EVR address: ") + address);

    std::vector<std::string> qualifiers;

    // This function forces a FlushStateToDisk so that a database scan and occur
    if (!prestricteddb->GetAddressQualifiers(address, qualifiers)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to search the database");
    }

    UniValue ret(UniValue::VARR);
    for (auto item : qualifiers) {
        ret.push_back(item);
    }

    return ret;
}

UniValue listaddressesfortag(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 1)
        throw std::runtime_error(
                "listaddressesfortag tag_name\n"
                + RestrictedActivationWarning() +
                "\nList all addresses that have been assigned a given tag\n"

                "\nArguments:\n"
                "1. \"tag_name\"          (string, required) the tag asset name to search for\n"

                "\nResult:\n"
                "["
                "\"address\",        (string) The address\n"
                "...,\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listaddressesfortag", "\"#TAG\"")
                + HelpExampleRpc("listaddressesfortag", "\"#TAG\"")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    std::string qualifier_name = request.params[0].get_str();

    if (!IsAssetNameAQualifier(qualifier_name))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "You must use qualifier asset names only, qualifier assets start with '#'");


    std::vector<std::string> addresses;

    // This function forces a FlushStateToDisk so that a database scan and occur
    if (!prestricteddb->GetQualifierAddresses(qualifier_name, addresses)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to search the database");
    }

    UniValue ret(UniValue::VARR);
    for (auto item : addresses) {
        ret.push_back(item);
    }

    return ret;
}

UniValue listaddressrestrictions(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() !=1)
        throw std::runtime_error(
                "listaddressrestrictions address\n"
                + RestrictedActivationWarning() +
                "\nList all assets that have frozen this address\n"

                "\nArguments:\n"
                "1. \"address\"          (string), required) the address to list restrictions for\n"

                "\nResult:\n"
                "["
                "\"asset_name\",        (string) The restriction name\n"
                "...,\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listaddressrestrictions", "\"address\"")
                + HelpExampleRpc("listaddressrestrictions", "\"address\"")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    std::string address = request.params[0].get_str();

    // Check to make sure the given from address is valid
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Not valid EVR address: ") + address);

    std::vector<std::string> restrictions;

    if (!prestricteddb->GetAddressRestrictions(address, restrictions)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to search the database");
    }

    UniValue ret(UniValue::VARR);
    for (auto item : restrictions) {
        ret.push_back(item);
    }

    return ret;
}

UniValue listglobalrestrictions(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 0)
        throw std::runtime_error(
                "listglobalrestrictions\n"
                + RestrictedActivationWarning() +
                "\nList all global restricted assets\n"


                "\nResult:\n"
                "["
                "\"asset_name\", (string) The asset name\n"
                "...,\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listglobalrestrictions", "")
                + HelpExampleRpc("listglobalrestrictions", "")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    std::vector<std::string> restrictions;

    if (!prestricteddb->GetGlobalRestrictions(restrictions)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to search the database");
    }

    UniValue ret(UniValue::VARR);
    for (auto item : restrictions) {
        ret.push_back(item);
    }

    return ret;
}

UniValue getverifierstring(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 1)
        throw std::runtime_error(
                "getverifierstring restricted_name\n"
                + RestrictedActivationWarning() +
                "\nRetrieve the verifier string that belongs to the given restricted asset\n"

                "\nArguments:\n"
                "1. \"restricted_name\"          (string, required) the asset_name\n"

                "\nResult:\n"
                "\"verifier_string\", (string) The verifier for the asset\n"

                "\nExamples:\n"
                + HelpExampleCli("getverifierstring", "\"restricted_name\"")
                + HelpExampleRpc("getverifierstring", "\"restricted_name\"")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    if (!passets) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Assets cache not available");
    }

    std::string asset_name = request.params[0].get_str();

    CNullAssetTxVerifierString verifier;
    if (!passets->GetAssetVerifierStringIfExists(asset_name, verifier))
        throw JSONRPCError(RPC_INVALID_PARAMETER, _("Verifier not found for asset: ") + asset_name);

    return verifier.verifier_string;
}

UniValue getp2ahaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getp2ahaddress \"asset_name!\"\n"
            "\nReturn the P2AH address (A-prefixed) derived from the administrative asset name.\n"
            "\nArguments:\n"
            "1. \"asset_name!\"   (string, required) Administrative asset name ending with !\n"
        );

    std::string assetName = request.params[0].get_str();
    AssetType at;
    std::string err;
    if (!IsAssetNameValid(assetName, at, err) || !IsAssetNameAnOwner(assetName)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid administrative asset name: ") + assetName + (err.empty()?"":(" ("+err+")")));
    }

    // Build canonical P2AH redeemScript: OP_EVR_ASSET <hash(ASSET!)> OP_DROP OP_TRUE
    uint160 h160 = HashAssetNameTo160(assetName);
    CScript redeem;
    redeem << OP_EVR_ASSET << ToByteVector(h160) << OP_DROP << OP_TRUE;
    // Store in wallet keystore if available
    if (CWallet * const pwallet = GetWalletForJSONRPCRequest(request)) {
        LOCK(pwallet->cs_wallet);
        pwallet->AddCScript(redeem);
    }
    uint160 scriptHash = CScriptID(redeem);
    // A-prefixed: use ASSET_ADDRESS version with redeemScript hash
    std::string address = EncodeDestination(CAssetID(scriptHash));
    std::string scriptAddress = EncodeDestination(CScriptID(redeem));
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("asset", assetName));
    result.push_back(Pair("address", address));
    result.push_back(Pair("scriptAddress", scriptAddress));
    result.push_back(Pair("redeemScript", HexStr(redeem.begin(), redeem.end())));
    return result;
}

static UniValue createp2ahaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "createp2ahaddress [\"ASSET1!\",...] (nrequired) ([\"pubkey1\",...])\n"
            "\nCreate a P2AH redeem script requiring inclusion of one or more owner assets and optional m-of-n multisig.\n"
            "Returns A-prefixed address, P2SH address, and redeemScript.\n"
        );

    // Parse owner assets
    std::vector<std::string> assetNames;
    if (request.params[0].isStr()) assetNames.push_back(request.params[0].get_str());
    else if (request.params[0].isArray()) {
        for (const auto& v : request.params[0].get_array().getValues()) assetNames.push_back(v.get_str());
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "First param must be string or array of strings");
    }
    if (assetNames.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "At least one owner asset is required");
    for (const auto& name : assetNames) {
        AssetType at; std::string err;
        if (!IsAssetNameValid(name, at, err) || !IsAssetNameAnOwner(name))
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid owner asset: ") + name);
    }

    int nrequired = 0;
    if (request.params.size() > 1 && !request.params[1].isNull()) nrequired = request.params[1].get_int();

    std::vector<CPubKey> keys;
    if (request.params.size() > 2 && request.params[2].isArray()) {
        for (const auto& v : request.params[2].get_array().getValues()) {
            std::vector<unsigned char> vch = ParseHex(v.get_str());
            CPubKey pk(vch.begin(), vch.end());
            if (!pk.IsValid()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid pubkey in array");
            keys.push_back(pk);
        }
    }
    if (nrequired < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "nrequired must be >= 0");
    if (nrequired > 0 && (keys.empty() || nrequired > (int)keys.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "nrequired must be <= number of pubkeys and > 0");

    // Build redeemScript: [OP_EVR_ASSET h160 OP_DROP]* then payload (multisig or OP_TRUE)
    CScript redeem;
    for (const auto& name : assetNames) {
        redeem << OP_EVR_ASSET << ToByteVector(HashAssetNameTo160(name)) << OP_DROP;
    }
    if (nrequired > 0)
        redeem += GetScriptForMultisig(nrequired, keys);
    else
        redeem << OP_TRUE;

    // Store in keystore if available and persist mapping of expected assets
    std::string joined;
    for (size_t i = 0; i < assetNames.size(); ++i) { if (i) joined.push_back(','); joined += assetNames[i]; }
    CTxDestination p2shDest = CScriptID(redeem);
    CTxDestination p2ahDest = CAssetID(CScriptID(redeem));
    if (CWallet * const pwallet = GetWalletForJSONRPCRequest(request)) {
        LOCK(pwallet->cs_wallet);
        pwallet->AddCScript(redeem);
        pwallet->AddDestData(p2shDest, "p2ah_assets", joined);
        pwallet->AddDestData(p2ahDest, "p2ah_assets", joined);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", EncodeDestination(p2ahDest)));
    result.push_back(Pair("scriptAddress", EncodeDestination(p2shDest)));
    result.push_back(Pair("redeemScript", HexStr(redeem.begin(), redeem.end())));
    return result;
}

UniValue checkaddresstag(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 2)
        throw std::runtime_error(
                "checkaddresstag address tag_name\n"
                + RestrictedActivationWarning() +
                "\nChecks to see if an address has the given tag\n"

                "\nArguments:\n"
                "1. \"address\"          (string, required) the EVR address to search\n"
                "1. \"tag_name\"         (string, required) the tag to search\n"

                "\nResult:\n"
                "\"true/false\", (boolean) If the address has the tag\n"

                "\nExamples:\n"
                + HelpExampleCli("checkaddresstag", "\"address\" \"tag_name\"")
                + HelpExampleRpc("checkaddresstag", "\"address\" \"tag_name\"")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    if (!passetsQualifierCache)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Qualifier cache not available");

    if (!passets)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Asset cache not available");


    std::string address = request.params[0].get_str();
    std::string qualifier_name = request.params[1].get_str();

    // Check to make sure the given from address is valid
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Not valid EVR address: ") + address);

    return passets->CheckForAddressQualifier(qualifier_name, address);
}

UniValue checkaddressrestriction(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 2)
        throw std::runtime_error(
                "checkaddressrestriction address restricted_name\n"
                + RestrictedActivationWarning() +
                "\nChecks to see if an address has been frozen by the given restricted asset\n"

                "\nArguments:\n"
                "1. \"address\"          (string, required) the EVR address to search\n"
                "1. \"restricted_name\"   (string, required) the restricted asset to search\n"

                "\nResult:\n"
                "\"true/false\", (boolean) If the address is frozen\n"

                "\nExamples:\n"
                + HelpExampleCli("checkaddressrestriction", "\"address\" \"restricted_name\"")
                + HelpExampleRpc("checkaddressrestriction", "\"address\" \"restricted_name\"")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    if (!passetsRestrictionCache)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restriction cache not available");

    if (!passets)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Asset cache not available");

    std::string address = request.params[0].get_str();
    std::string restricted_name = request.params[1].get_str();

    // Check to make sure the given from address is valid
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Not valid EVR address: ") + address);

    return passets->CheckForAddressRestriction(restricted_name, address);
}

UniValue checkglobalrestriction(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 1)
        throw std::runtime_error(
                "checkglobalrestriction restricted_name\n"
                + RestrictedActivationWarning() +
                "\nChecks to see if a restricted asset is globally frozen\n"

                "\nArguments:\n"
                "1. \"restricted_name\"   (string, required) the restricted asset to search\n"

                "\nResult:\n"
                "\"true/false\", (boolean) If the restricted asset is frozen globally\n"

                "\nExamples:\n"
                + HelpExampleCli("checkglobalrestriction", "\"restricted_name\"")
                + HelpExampleRpc("checkglobalrestriction", "\"restricted_name\"")
        );

    if (!prestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restricted asset database not available");

    if (!passetsGlobalRestrictionCache)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Restriction cache not available");

    if (!passets)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Asset cache not available");

    std::string restricted_name = request.params[0].get_str();

    return passets->CheckForGlobalRestriction(restricted_name, true);
}

#ifdef ENABLE_WALLET

UniValue issuequalifierasset(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 1 || request.params.size() > 7)
        throw std::runtime_error(
                "issuequalifierasset \"asset_name\" qty \"( to_address )\" \"( change_address )\" ( has_ipfs ) \"( ipfs_hash )\" \"( permanent_ipfs_hash )\"\n"
                + RestrictedActivationWarning() +
                "\nIssue a qualifier or sub-qualifier asset.\n"
                "If the '#' character isn't added, it will be added automatically.\n"
                "Amount is a number between 1 and 10.\n"
                "Asset name must not conflict with any existing asset.\n"
                "Unit is always set to Zero (0) for qualifier assets.\n"
                "Reissuable is always set to false for qualifier assets.\n"

                "\nArguments:\n"
                "1. \"asset_name\"            (string, required) a unique name.\n"
                "2. \"qty\"                   (numeric, optional, default=1) the number of units to be issued.\n"
                "3. \"to_address\"            (string, optional, default=\"\") address asset will be sent to; if empty, an address will be generated for you.\n"
                "4. \"change_address\"        (string, optional, default=\"\") address where Evr change will be sent to; if empty, a change address will be generated for you.\n"
                "5. \"has_ipfs\"              (boolean, optional, default=false) whether an IPFS hash is going to be added to the asset.\n"
                "6. \"ipfs_hash\"             (string, optional but required if has_ipfs = 1) an IPFS hash or txid hash once RIP5 is activated.\n"
                "7. \"permanent_ipfs_hash\"   (string, optional) a permanent IPFS hash for the asset.\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction ID.\n"

                "\nExamples:\n"
                + HelpExampleCli("issuequalifierasset", "\"#ASSET_NAME\" 1000")
                + HelpExampleCli("issuequalifierasset", "\"ASSET_NAME\" 1000 \"myaddress\"")
                + HelpExampleCli("issuequalifierasset", "\"#ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\"")
                + HelpExampleCli("issuequalifierasset", "\"#ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E")
                + HelpExampleCli("issuequalifierasset", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E QmPermanentHash 0.01 \"tollAddress\" true true")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Check asset name and infer assetType
    std::string assetName = request.params[0].get_str();
    if (!IsAssetNameAQualifier(assetName)) {
        assetName = QUALIFIER_CHAR + assetName;
    }

    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameValid(assetName, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + assetName + "\nError: " + assetError);
    }

    if (assetType != AssetType::QUALIFIER && assetType != AssetType::SUB_QUALIFIER) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unsupported asset type: " + AssetTypeToString(assetType) + " Please use a valid qualifier name.");
    }

    CAmount nAmount = COIN;
    if (request.params.size() > 1) {
        nAmount = AmountFromValue(request.params[1]);
    }

    if (nAmount < QUALIFIER_ASSET_MIN_AMOUNT || nAmount > QUALIFIER_ASSET_MAX_AMOUNT) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters for issuing a qualifier asset. Amount must be between 1 and 10.");
    }

    std::string address = "";
    if (request.params.size() > 2) {
        address = request.params[2].get_str();
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Evrmore address: " + address);
        }
    } else {
        // Generate a new address if not provided
        if (!pwallet->IsLocked()) {
            pwallet->TopUpKeyPool();
        }

        CPubKey newKey;
        if (!pwallet->GetKeyFromPool(newKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first.");
        }
        CKeyID keyID = newKey.GetID();
        address = EncodeDestination(keyID);
        pwallet->SetAddressBook(keyID, "", "receive");
    }

    std::string change_address = "";
    if (request.params.size() > 3) {
        change_address = request.params[3].get_str();
        if (!change_address.empty()) {
            CTxDestination destination = DecodeDestination(change_address);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Evrmore address: " + change_address);
            }
        }
    }

    bool has_ipfs = false;
    if (request.params.size() > 4) {
        has_ipfs = request.params[4].get_bool();
    }

    std::string ipfs_hash = "";
    if (request.params.size() > 5 && has_ipfs) {
        ipfs_hash = request.params[5].get_str();
        if (!ipfs_hash.empty())
            CheckIPFSTxidMessage(ipfs_hash, 0);
    }

    std::string permanent_ipfs_hash = request.params.size() > 6 ? request.params[6].get_str() : "";
    if (!permanent_ipfs_hash.empty())
        CheckIPFSTxidMessage(permanent_ipfs_hash, 0);

    // Units are zero, and reissuable is false
    CNewAsset asset(assetName, nAmount, 0, 0, has_ipfs ? 1 : 0,
                    DecodeAssetData(ipfs_hash), DecodeAssetData(permanent_ipfs_hash),
                    0, "", 0, 0, 0);

    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    std::pair<int, std::string> error;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(change_address);

    if (!CreateAssetTransaction(pwallet, crtl, asset, address, error, transaction, reservekey, nRequiredFee)) {
        throw JSONRPCError(error.first, error.second);
    }

    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid)) {
        throw JSONRPCError(error.first, error.second);
    }

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}


UniValue issuerestrictedasset(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 4 || request.params.size() > 15)
        throw std::runtime_error(
                "issuerestrictedasset \"asset_name\" qty \"verifier\" \"to_address\" \"( change_address )\" (units) ( reissuable ) ( has_ipfs ) \"( ipfs_hash )\" \"( permanent_ipfs_hash )\" ( toll_amount ) \"( toll_address )\" ( toll_amount_mutability ) ( toll_address_mutability ) ( remintable )\n"
                + RestrictedActivationWarning() +
                "\nIssue a restricted asset.\n"
                "Restricted asset names must not conflict with any existing restricted asset.\n"
                "Restricted assets have units set to 0.\n"
                "Reissuable is true/false for whether additional asset quantity can be created and if the verifier string can be changed.\n"

                "\nArguments:\n"
                "1. \"asset_name\"            (string, required) a unique name, starts with '$', if '$' is not there it will be added automatically.\n"
                "2. \"qty\"                   (numeric, required) the quantity of the asset to be issued.\n"
                "3. \"verifier\"              (string, required) the verifier string that will be evaluated when restricted asset transfers are made.\n"
                "4. \"to_address\"            (string, required) address asset will be sent to, this address must meet the verifier string requirements.\n"
                "5. \"change_address\"        (string, optional, default=\"\") address that the evr change will be sent to, if it is empty, change address will be generated for you.\n"
                "6. \"units\"                 (integer, optional, default=0, min=0, max=8) the number of decimals precision for the asset (0 for whole units (\"1\"), 8 for max precision (\"1.00000000\").\n"
                "7. \"reissuable\"            (boolean, optional, default=true (false for unique assets)) whether future reissuance is allowed.\n"
                "8. \"has_ipfs\"              (boolean, optional, default=false) whether an IPFS hash or txid hash is going to be added to the asset.\n"
                "9. \"ipfs_hash\"             (string, optional but required if has_ipfs = 1) an IPFS hash or a txid hash once RIP5 is activated.\n"
                "10. \"permanent_ipfs_hash\"  (string, optional) a permanent IPFS hash for the asset.\n"
                "11. \"toll_amount\"          (numeric, optional, default=0) the amount of toll fee to be assigned to the asset.\n"
                "12. \"toll_address\"         (string, optional, default=\"\") address to receive the toll fee, if it is empty, the default toll address will be used.\n"
                "13. \"toll_amount_mutability\" (boolean, optional, default=false) whether future changing is allowed for the toll amount.\n"
                "14. \"toll_address_mutability\" (boolean, optional, default=false) whether future changing is allowed for the toll address.\n"
                "15. \"remintable\" (boolean, optional, default=true) whether the ability to remint assets that are burned is allowed.\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction ID.\n"

                "\nExamples:\n"
                + HelpExampleCli("issuerestrictedasset", "\"$ASSET_NAME\" 1000 \"#KYC & !#AML\" \"myaddress\"")
                + HelpExampleCli("issuerestrictedasset", "\"$ASSET_NAME\" 1000 \"#KYC & !#AML\" \"myaddress\" \"changeaddress\" 5")
                + HelpExampleCli("issuerestrictedasset", "\"$ASSET_NAME\" 1000 \"#KYC & !#AML\" \"myaddress\" \"changeaddress\" 8 true")
                + HelpExampleCli("issuerestrictedasset", "\"$ASSET_NAME\" 1000 \"#KYC & !#AML\" \"myaddress\" \"changeaddress\" 0 false true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E")
                + HelpExampleCli("issuerestrictedasset", "\"$ASSET_NAME\" 1000 \"#KYC & !#AML\" \"myaddress\" \"changeaddress\" 0 false true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E QmPermanentHash 0.01 \"tollAddress\" true true true")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Check asset name and infer assetType
    std::string assetName = request.params[0].get_str();
    AssetType assetType;
    std::string assetError = "";

    if (!IsAssetNameAnRestricted(assetName)) {
        assetName = RESTRICTED_CHAR + assetName;
    }

    if (!IsAssetNameValid(assetName, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + assetName + "\nError: " + assetError);
    }

    if (assetType != AssetType::RESTRICTED) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unsupported asset type: ") + AssetTypeToString(assetType));
    }

    // Parse required parameters
    CAmount nAmount = AmountFromValue(request.params[1]);
    std::string verifier_string = request.params[2].get_str();
    std::string to_address = request.params[3].get_str();

    // Validate the address
    CTxDestination destination = DecodeDestination(to_address);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + to_address);
    }

    std::string verifierStripped = GetStrippedVerifierString(verifier_string);

    // Validate the verifier string with the given to_address
    std::string strError = "";
    if (!ContextualCheckVerifierString(passets, verifierStripped, to_address, strError))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strError);

    // Parse optional parameters
    std::string change_address = request.params.size() > 4 ? request.params[4].get_str() : "";
    if (!change_address.empty()) {
        CTxDestination changeDest = DecodeDestination(change_address);
        if (!IsValidDestination(changeDest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Change Address: Invalid Evrmore address: " + change_address);
        }
    }

    int units = request.params.size() > 5 ? request.params[5].get_int() : MIN_UNIT;
    if (units < MIN_UNIT || units > MAX_UNIT)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Units must be between 0 and 8");

    bool reissuable = request.params.size() > 6 ? request.params[6].get_bool() : true;
    bool has_ipfs = request.params.size() > 7 ? request.params[7].get_bool() : false;

    // Validate IPFS hash
    std::string ipfs_hash = "";
    if (request.params.size() > 8 && has_ipfs) {
        ipfs_hash = request.params[8].get_str();
        if (!ipfs_hash.empty())
            CheckIPFSTxidMessage(ipfs_hash, 0);
    }

    // New parameters
    std::string permanent_ipfs_hash = request.params.size() > 9 ? request.params[9].get_str() : "";
    if (!permanent_ipfs_hash.empty())
        CheckIPFSTxidMessage(permanent_ipfs_hash, 0);

    CAmount toll_amount = request.params.size() > 10 ? AmountFromValue(request.params[10]) : 0;
    std::string toll_address = request.params.size() > 11 ? request.params[11].get_str() : "";
    if (!toll_address.empty()) {
        CTxDestination tollDest = DecodeDestination(toll_address);
        if (!IsValidDestination(tollDest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Toll Address: Invalid Evrmore address: " + toll_address);
        }
    }

    bool toll_amount_mutability = request.params.size() > 12 ? request.params[12].get_bool() : false;
    bool toll_address_mutability = request.params.size() > 13 ? request.params[13].get_bool() : false;
    bool remintable = request.params.size() > 14 ? request.params[14].get_bool() : true;

    // If tolls isn't active, don't set the remintable variable, because it would be a v2 asset, and get rejected
    if(!IsTollsActive()) {
        remintable = false;
    }

    CNewAsset asset(assetName, nAmount, units, reissuable ? 1 : 0, has_ipfs ? 1 : 0,
                    DecodeAssetData(ipfs_hash), DecodeAssetData(permanent_ipfs_hash),
                    toll_amount, toll_address, toll_amount_mutability, toll_address_mutability, remintable);

    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    std::pair<int, std::string> error;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(change_address);

    // Create the Transaction
    if (!CreateAssetTransaction(pwallet, crtl, asset, to_address, error, transaction, reservekey, nRequiredFee, &verifierStripped))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue reissuerestrictedasset(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() < 3 || request.params.size() > 15)
        throw std::runtime_error(
                "reissuerestrictedasset \"asset_name\" qty to_address ( change_verifier ) ( \"new_verifier\" ) \"( change_address )\" ( new_units ) ( reissuable ) \"( new_ipfs )\" \"( permanent_ipfs )\" ( change_toll_amount ) ( toll_amount ) \"( toll_address ) ( toll_amount_mutability ) ( toll_address_mutability )\"\n"
                + RestrictedActivationWarning() +
                "\nReissue an already created restricted asset.\n"
                "Reissuable is true/false for whether additional asset quantity can be created and if the verifier string can be changed.\n"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of the restricted asset to be reissued.\n"
                "2. \"qty\"                      (numeric, required) the additional quantity of the asset to be issued.\n"
                "3. \"to_address\"               (string, required) address asset will be sent to; this address must meet the verifier string requirements.\n"
                "4. \"change_verifier\"          (boolean, optional, default=false) whether the verifier string will get changed.\n"
                "5. \"new_verifier\"             (string, optional, default=\"\") the new verifier string.\n"
                "6. \"change_address\"           (string, optional, default=\"\") address that the Evr change will be sent to; if empty, a change address will be generated.\n"
                "7. \"new_units\"                (numeric, optional, default=-1) the new units for the asset.\n"
                "8. \"reissuable\"               (boolean, optional, default=true) whether future reissuance is allowed.\n"
                "9. \"new_ipfs\"                 (string, optional, default=\"\") new IPFS hash or txid.\n"
                "10. \"permanent_ipfs\"          (string, optional, default=\"\") new permanent IPFS hash for the asset.\n"
                "11. \"change_toll_amount\"      (boolean, optional, default=false) whether the toll amount is being changed.\n"
                "12. \"toll_amount\"             (numeric, optional, default=0) the toll amount to be associated with the asset.\n"
                "13. \"toll_address\"            (string, optional, default=\"\") the toll address for the asset.\n"
                "14. \"toll_amount_mutability\"  (boolean, optional, default=true) whether future changing is allowed on toll amount.\n"
                "15. \"toll_address_mutability\" (boolean, optional, default=true) whether future changing is allowed on toll address.\n"

                "\nResult:\n"
                "\"txid\"                        (string) The transaction ID.\n"

                "\nExamples:\n"
                + HelpExampleCli("reissuerestrictedasset", "\"$ASSET_NAME\" 1000 \"myaddress\" true \"KYC & !AML\"")
                + HelpExampleCli("reissuerestrictedasset", "\"$ASSET_NAME\" 1000 \"myaddress\" false \"\" \"changeaddress\" -1 true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E QmPermanentHash true 100 \"toll_address\" true true")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Parse parameters
    std::string assetName = request.params[0].get_str();
    CAmount nAmount = AmountFromValue(request.params[1]);
    std::string to_address = request.params[2].get_str();
    bool fChangeVerifier = request.params.size() > 3 ? request.params[3].get_bool() : false;
    std::string verifier_string = request.params.size() > 4 ? request.params[4].get_str() : "";
    std::string change_address = request.params.size() > 5 ? request.params[5].get_str() : "";
    int newUnits = request.params.size() > 6 ? request.params[6].get_int() : -1;
    bool reissuable = request.params.size() > 7 ? request.params[7].get_bool() : true;
    std::string new_ipfs_data = request.params.size() > 8 ? request.params[8].get_str() : "";
    std::string permanent_ipfs = request.params.size() > 9 ? request.params[9].get_str() : "";
    bool change_toll_amount = request.params.size() > 10 ? request.params[10].get_bool() : false;
    CAmount toll_amount = request.params.size() > 11 ? AmountFromValue(request.params[11]) : 0;
    std::string toll_address = request.params.size() > 12 ? request.params[12].get_str() : "";
    bool toll_amount_mutability = request.params.size() > 13 ? request.params[13].get_bool() : true;
    bool toll_address_mutability = request.params.size() > 14 ? request.params[14].get_bool() : true;

    // Validate asset name and address
    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameAnRestricted(assetName)) {
        assetName = RESTRICTED_CHAR + assetName;
    }
    if (!IsAssetNameValid(assetName, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset name: " + assetName + "\nError: " + assetError);
    }
    if (assetType != AssetType::RESTRICTED) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unsupported asset type: " + AssetTypeToString(assetType));
    }

    CTxDestination to_dest = DecodeDestination(to_address);
    if (!IsValidDestination(to_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Evrmore address: " + to_address);
    }

    if (!change_address.empty()) {
        CTxDestination change_dest = DecodeDestination(change_address);
        if (!IsValidDestination(change_dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Evrmore address: " + change_address);
        }
    }

    if (!toll_address.empty()) {
        CTxDestination toll_dest = DecodeDestination(toll_address);
        if (!IsValidDestination(toll_dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Toll Address: " + toll_address);
        }
    }

    if (newUnits < -1 || newUnits > MAX_UNIT) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Units must be between -1 and 8; -1 means don't change the current units.");
    }

    // Validate IPFS hashes
    if (!new_ipfs_data.empty()) {
        CheckIPFSTxidMessage(new_ipfs_data, 0);
    }
    if (!permanent_ipfs.empty()) {
        CheckIPFSTxidMessage(permanent_ipfs, 0);
    }

    // Reissuing rpc call can't be used to remint
    // Use remint rpccall
    bool reminting_asset = false;

    // Don't change this value if it is already true
    bool remintable = true;

    // Create the reissue asset object
    CReissueAsset reissueAsset(assetName, nAmount, newUnits, reissuable,
                               DecodeAssetData(new_ipfs_data), DecodeAssetData(permanent_ipfs),
                               change_toll_amount, toll_amount, toll_address, reminting_asset,
                               toll_amount_mutability, toll_address_mutability, remintable);

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;
    std::pair<int, std::string> error;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(change_address);

    std::string verifierStripped = GetStrippedVerifierString(verifier_string);

    if (!CreateReissueAssetTransaction(pwallet, crtl, reissueAsset, to_address, error, transaction, reservekey, nRequiredFee, fChangeVerifier ? &verifierStripped : nullptr)) {
        throw JSONRPCError(error.first, error.second);
    }

    if (!ContextualCheckReissueAsset(passets, reissueAsset, assetError, *transaction.tx.get())) {
        throw JSONRPCError(RPC_INVALID_REQUEST, assetError);
    }

    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid)) {
        throw JSONRPCError(error.first, error.second);
    }

    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue transferqualifier(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 3 || request.params.size() > 6)
        throw std::runtime_error(
                "transferqualifier \"qualifier_name\" qty \"to_address\" (\"change_address\") (\"message\") (expire_time) \n"
                + RestrictedActivationWarning() +
                "\nTransfer a qualifier asset owned by this wallet to the given address"

                "\nArguments:\n"
                "1. \"qualifier_name\"           (string, required) name of qualifier asset\n"
                "2. \"qty\"                      (numeric, required) number of assets you want to send to the address\n"
                "3. \"to_address\"               (string, required) address to send the asset to\n"
                "4. \"change_address\"           (string, optional, default = \"\") the transaction change will be sent to this address\n"
                "5. \"message\"                  (string, optional) Once RIP5 is voted in ipfs hash or txid hash to send along with the transfer\n"
                "6. \"expire_time\"              (numeric, optional) UTC timestamp of when the message expires\n"

                "\nResult:\n"
                "txid"
                "[ \n"
                "txid\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("transferqualifier", "\"#QUALIFIER\" 20 \"to_address\" \"\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 15863654")
                + HelpExampleCli("transferqualifier", "\"#QUALIFIER\" 20 \"to_address\" \"change_address\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 15863654")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();

    if (!IsAssetNameAQualifier(asset_name))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Only use this rpc call to send Qualifier assets. Qualifier assets start with the character '#'");

    CAmount nAmount = AmountFromValue(request.params[1]);

    std::string to_address = request.params[2].get_str();
    CTxDestination to_dest = DecodeDestination(to_address);
    if (!IsValidDestination(to_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + to_address);
    }

    std::string change_address = "";
    if(request.params.size() > 3) {
        change_address = request.params[3].get_str();

        CTxDestination change_dest = DecodeDestination(change_address);
        if (!IsValidDestination(change_dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Evrmore address: ") + change_address);
        }
    }

    if (request.params.size() > 4) {
        if (!AreMessagesDeployed()) {
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Unable to send messages until Messaging RIP5 is enabled"));
        }
    }

    bool fMessageCheck = false;
    std::string message = "";
    if (request.params.size() > 4) {
        fMessageCheck = true;
        message = request.params[4].get_str();
    }

    int64_t expireTime = 0;
    if (!message.empty()) {
        if (request.params.size() > 5) {
            expireTime = request.params[5].get_int64();
        }
    }

    if (fMessageCheck)
        CheckIPFSTxidMessage(message, expireTime);

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    CAssetTransfer transfer(asset_name, nAmount, DecodeAssetData(message), expireTime);

    vTransfers.emplace_back(std::make_pair(transfer, to_address));
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    ctrl.destChange = DecodeDestination(change_address);

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}
#endif

UniValue isvalidverifierstring(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 1)
        throw std::runtime_error(
                "isvalidverifierstring verifier_string\n"
                + RestrictedActivationWarning() +
                "\nChecks to see if the given verifier string is valid\n"

                "\nArguments:\n"
                "1. \"verifier_string\"   (string, required) the verifier string to check\n"

                "\nResult:\n"
                "\"xxxxxxx\", (string) If the verifier string is valid, and the reason\n"

                "\nExamples:\n"
                + HelpExampleCli("isvalidverifierstring", "\"verifier_string\"")
                + HelpExampleRpc("isvalidverifierstring", "\"verifier_string\"")
        );

    ObserveSafeMode();
    LOCK(cs_main);

    if (!passets)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Asset cache not available");

    std::string verifier_string = request.params[0].get_str();

    std::string stripped_verifier_string = GetStrippedVerifierString(verifier_string);

    std::string strError;
    if (!ContextualCheckVerifierString(passets, stripped_verifier_string, "", strError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
    }

    return _("Valid Verifier");
}

UniValue getsnapshot(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 2)
        throw std::runtime_error(
                "getsnapshot \"asset_name\" block_height\n"
                + AssetActivationWarning() +
                "\nReturns details for the asset snapshot, at the specified height\n"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) the name of the asset\n"
                "2. block_height                 (int, required) the block height of the snapshot\n"

                "\nResult:\n"
                "{\n"
                "  name: (string),\n"
                "  height: (number),\n"
                "  owners: [\n"
                "    {\n"
                "      address: (string),\n"
                "      amount_owned: (number),\n"
                "    }\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleRpc("getsnapshot", "\"ASSET_NAME\" 28546")
        );


    std::string asset_name = request.params[0].get_str();
    int block_height = request.params[1].get_int();

    if (!pAssetSnapshotDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, std::string("Asset Snapshot database is not setup. Please restart wallet to try again"));

    LOCK(cs_main);
    UniValue result (UniValue::VOBJ);

    CAssetSnapshotDBEntry snapshotDbEntry;

    if (pAssetSnapshotDb->RetrieveOwnershipSnapshot(asset_name, block_height, snapshotDbEntry)) {
        result.push_back(Pair("name", snapshotDbEntry.assetName));
        result.push_back(Pair("height", snapshotDbEntry.height));

        UniValue entries(UniValue::VARR);
        for (auto const & ownerAndAmt : snapshotDbEntry.ownersAndAmounts) {
            UniValue entry(UniValue::VOBJ);

            entry.push_back(Pair("address", ownerAndAmt.first));
            entry.push_back(Pair("amount_owned", UnitValueFromAmount(ownerAndAmt.second, snapshotDbEntry.assetName)));

            entries.push_back(entry);
        }

        result.push_back(Pair("owners", entries));

        return result;
    }

    return NullUniValue;
}

UniValue purgesnapshot(const JSONRPCRequest& request)
{
    if (request.fHelp || !AreAssetsDeployed() || request.params.size() < 2)
        throw std::runtime_error(
                "purgesnapshot \"asset_name\" block_height\n"
                + AssetActivationWarning() +
                "\nRemoves details for the asset snapshot, at the specified height\n"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) the name of the asset\n"
                "2. block_height                 (int, required) the block height of the snapshot\n"

                "\nResult:\n"
                "{\n"
                "  name: (string),\n"
                "  height: (number),\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("purgesnapshot", "\"ASSET_NAME\" 28546")
                + HelpExampleRpc("purgesnapshot", "\"ASSET_NAME\" 28546")
        );


    std::string asset_name = request.params[0].get_str();
    int block_height = 0;
    if (request.params.size() > 1) {
        block_height = request.params[2].get_int();
    }

    if (!pAssetSnapshotDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, std::string("Asset Snapshot database is not setup. Please restart wallet to try again"));

    LOCK(cs_main);
    UniValue result (UniValue::VOBJ);

    if (pAssetSnapshotDb->RemoveOwnershipSnapshot(asset_name, block_height)) {
        result.push_back(Pair("name", asset_name));
        if (block_height > 0) {
            result.push_back(Pair("height", block_height));
        }

        return result;
    }

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category    name                          actor (function)             argNames
  //  ----------- ------------------------      -----------------------      ----------
#ifdef ENABLE_WALLET
    { "assets",   "issue",                      &issue,                      {"asset_name","qty","to_address","change_address","units","reissuable","has_ipfs","ipfs_hash","permanent_ipfs_hash", "toll_amount", "toll_address", "toll_amount_mutability", "toll_address_mutability", "remintable"}},
    { "assets",   "issueunique",                &issueunique,                {"root_name", "asset_tags", "ipfs_hashes", "to_address", "change_address", "permanent_ipfs_hash", "toll_amount", "toll_address", "toll_amount_mutability", "toll_address_mutability"}},
    { "assets",   "listmyassets",               &listmyassets,               {"asset", "verbose", "count", "start", "confs"}},
#endif
    { "assets",   "listassetbalancesbyaddress", &listassetbalancesbyaddress, {"address", "onlytotal", "count", "start"} },
    { "assets",   "getassetdata",               &getassetdata,               {"asset_name"}},
    { "assets",   "listaddressesbyasset",       &listaddressesbyasset,       {"asset_name", "onlytotal", "count", "start"}},
    { "assets",   "getcalculatedtoll",          &getcalculatedtoll,          {"asset_name", "amount", "change_amount", "overwrite_toll_fee"}},
#ifdef ENABLE_WALLET
    { "assets",   "transferfromaddress",        &transferfromaddress,        {"asset_name", "from_address", "qty", "to_address", "message", "expire_time", "evr_change_address", "asset_change_address"}},
    { "assets",   "transferfromaddresses",      &transferfromaddresses,      {"asset_name", "from_addresses", "qty", "to_address", "message", "expire_time", "evr_change_address", "asset_change_address"}},
    { "assets",   "transfer",                   &transfer,                   {"asset_name", "qty", "to_address", "message", "expire_time", "change_address", "asset_change_address"}},
    { "assets",   "reissue",                    &reissue,                    {"asset_name", "qty", "to_address", "change_address", "reissuable", "new_units", "new_ipfs", "permanent_ipfs", "change_toll_amount", "toll_amount", "toll_address", "toll_amount_mutability", "toll_address_mutability"}},
    { "assets",   "updatemetadata",             &updatemetadata,             {"asset_name", "change_address", "new_ipfs", "permanent_ipfs", "toll_address", "change_toll_amount", "toll_amount", "toll_amount_mutability", "toll_address_mutability"}},
    { "assets",   "remint",                     &remint,                     {"asset_name", "qty", "to_address", "change_address", "remintable"}},
#endif
    { "assets",   "listassets",                 &listassets,                 {"asset", "verbose", "count", "start"}},
    { "assets",   "getcacheinfo",               &getcacheinfo,               {}},
    { "assets",   "getburnaddresses",           &getburnaddresses,               {}},
    { "assets",   "getp2ahaddress",              &getp2ahaddress,              {"asset_name"}},
    { "assets",   "createp2ahaddress",           &createp2ahaddress,           {"asset_names","nrequired","pubkeys"}},
    // createp2ahaddress omitted for brevity; can be added here when we expose multisig support for P2AH building

#ifdef ENABLE_WALLET
    { "restricted assets",   "transferqualifier",          &transferqualifier,          {"qualifier_name", "qty", "to_address", "change_address", "message", "expire_time"}},
    { "restricted assets",   "issuerestrictedasset",       &issuerestrictedasset,       {"asset_name","qty","verifier","to_address","change_address","units","reissuable","has_ipfs","ipfs_hash","permanent_ipfs_hash","toll_amount","toll_address","toll_amount_mutability","toll_address_mutability"}},
    { "restricted assets",   "issuequalifierasset",        &issuequalifierasset,        {"asset_name","qty","to_address","change_address","has_ipfs","ipfs_hash","permanent_ipfs_hash","toll_amount","toll_address","toll_amount_mutability","toll_address_mutability"} },
    { "restricted assets",   "reissuerestrictedasset",     &reissuerestrictedasset,     {"asset_name", "qty", "change_verifier", "new_verifier", "to_address", "change_address", "new_units", "reissuable", "new_ipfs", "permanent_ipfs", "change_toll_amount", "toll_amount", "toll_address", "toll_amount_mutability", "toll_address_mutability"}},
    { "restricted assets",   "addtagtoaddress",            &addtagtoaddress,            {"tag_name", "to_address", "change_address", "asset_data"}},
    { "restricted assets",   "removetagfromaddress",       &removetagfromaddress,       {"tag_name", "to_address", "change_address", "asset_data"}},
    { "restricted assets",   "freezeaddress",              &freezeaddress,              {"asset_name", "address", "change_address", "asset_data"}},
    { "restricted assets",   "unfreezeaddress",            &unfreezeaddress,            {"asset_name", "address", "change_address", "asset_data"}},
    { "restricted assets",   "freezerestrictedasset",      &freezerestrictedasset,      {"asset_name", "change_address", "asset_data"}},
    { "restricted assets",   "unfreezerestrictedasset",    &unfreezerestrictedasset,    {"asset_name", "change_address", "asset_data"}},
#endif
    { "restricted assets",   "listaddressesfortag",        &listaddressesfortag,        {"tag_name"}},
    { "restricted assets",   "listtagsforaddress",         &listtagsforaddress,         {"address"}},
    { "restricted assets",   "listaddressrestrictions",    &listaddressrestrictions,    {"address"}},
    { "restricted assets",   "listglobalrestrictions",     &listglobalrestrictions,     {}},
    { "restricted assets",   "getverifierstring",          &getverifierstring,          {"restricted_name"}},
    { "restricted assets",   "checkaddresstag",            &checkaddresstag,            {"address", "tag_name"}},
    { "restricted assets",   "checkaddressrestriction",    &checkaddressrestriction,    {"address", "restricted_name"}},
    { "restricted assets",   "checkglobalrestriction",     &checkglobalrestriction,     {"restricted_name"}},
    { "restricted assets",   "isvalidverifierstring",      &isvalidverifierstring,      {"verifier_string"}},

    { "assets",   "getsnapshot",                &getsnapshot,                {"asset_name", "block_height"}},
    { "assets",   "purgesnapshot",              &purgesnapshot,              {"asset_name", "block_height"}},
};

void RegisterAssetRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
