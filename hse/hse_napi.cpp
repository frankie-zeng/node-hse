#include <string.h>
#include <stdio.h>
#include "hse_napi.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include "hse_interface.h"

#define DEBUG



Napi::FunctionReference HSE::constructor;


Napi::Object HSE::Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);
    
  Napi::Function func =
      DefineClass(env,
                  "HSE",
                  {
                   InstanceMethod("getVersion", &HSE::getVersion),
                   InstanceMethod("importSymKey", &HSE::importSymKey),
                   InstanceMethod("importPubKey", &HSE::importPubKey),
                   InstanceMethod("importPrivKey", &HSE::importPrivKey),
                   InstanceMethod("formatCatalog", &HSE::formatCatalog),
                   });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  exports.Set("HSE", func);
  return exports;
}
// #ifdef DEBUG
// static int openssl_mem_leak_cb(const char* str,size_t len,void* u){
//     char* buf=new char[len+1];
//     memcpy(buf,str,len);
//     buf[len]=0;
//     printf("%s\r\n",buf);
//     delete buf;
// }
// #endif

static char* getErrorMsg(unsigned long err){
    char* buf=new char[512];
    ERR_error_string_n(err,buf,512);
    return buf;
}
static hseEccCurveId_t getCurveId(int id){
    hseEccCurveId_t eccCurveId;
#ifdef DEBUG
    printf("curve nid:%d\r\n",id);
#endif
    switch(id){
        case NID_secp384r1:
            eccCurveId=HSE_EC_SEC_SECP384R1;
            break;
        case NID_secp521r1:
            eccCurveId=HSE_EC_SEC_SECP521R1;
            break;
        case NID_brainpoolP256r1:
            eccCurveId=HSE_EC_BRAINPOOL_BRAINPOOLP256R1;
            break;
        case NID_brainpoolP384r1:
            eccCurveId=HSE_EC_BRAINPOOL_BRAINPOOLP384R1;
            break;
        case NID_brainpoolP320r1:
            eccCurveId=HSE_EC_BRAINPOOL_BRAINPOOLP320R1;
            break;
        case NID_brainpoolP512r1:
            eccCurveId=HSE_EC_BRAINPOOL_BRAINPOOLP512R1;
            break;
        case NID_ED25519:
            eccCurveId=HSE_EC_25519_ED25519;
            break;
        default:
            eccCurveId=HSE_EC_CURVE_NONE;
            break;
    }
    return eccCurveId;
}
HSE::HSE(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<HSE>(info) {
#ifdef DEBUG
    CRYPTO_set_mem_debug(1);
#endif
    return;
}

Napi::Value HSE::getVersion(const Napi::CallbackInfo& info){
    return Napi::String::New(info.Env(),OpenSSL_version(OPENSSL_VERSION));
}

Napi::Value HSE::importPrivKey(const Napi::CallbackInfo& info){
    hseSrvDescriptor_t service;
    hseKeyInfo_t keyInfo;

    memset((void*)&service,0,sizeof(hseSrvDescriptor_t));
    memset((void*)&keyInfo,0,sizeof(hseKeyInfo_t));
    Napi::Object ret=Napi::Object::New(info.Env());

    uint32_t offset=info[0].As<Napi::Number>().Uint32Value();
    hseKeyHandle_t keyHandle=info[1].As<Napi::Number>().Uint32Value();
    Napi::Object i=info[2].As<Napi::Object>();
    
    keyInfo.keyFlags=i.Get("keyFlags").ToNumber().Uint32Value();
    keyInfo.keyCounter=i.Get("keyCounter").ToNumber().Uint32Value();
    keyInfo.smrFlags=i.Get("smrFlags").ToNumber().Uint32Value();
    keyInfo.keyType=i.Get("keyType").ToNumber().Uint32Value();

    if(i.Has("keyBitLen")){
        keyInfo.keyBitLen=i.Get("keyBitLen").ToNumber().Uint32Value();
    }else{
        keyInfo.keyBitLen=0;
    }
    std::string key=info[3].As<Napi::String>();
    BIO *keyMem = BIO_new_mem_buf(key.c_str(), -1);
    EVP_PKEY* evpKey;
    evpKey=PEM_read_bio_PrivateKey(keyMem,NULL,NULL,NULL);
    if(evpKey!=NULL){
        if(keyInfo.keyBitLen==0){
            keyInfo.keyBitLen=EVP_PKEY_bits(evpKey);
        }
#ifdef DEBUG
        printf("key bit len %d\r\n",keyInfo.keyBitLen);
#endif
        if(EVP_PKEY_base_id(evpKey)==EVP_PKEY_RSA){
            RSA* rsaKey=EVP_PKEY_get1_RSA(evpKey);
            keyInfo.specific.pubExponentSize=BN_num_bytes(RSA_get0_e(rsaKey));
            int nSize=BN_num_bytes(RSA_get0_n(rsaKey));
            int eSize=BN_num_bytes(RSA_get0_e(rsaKey));
            int dSize=BN_num_bytes(RSA_get0_d(rsaKey));
#ifdef DEBUG
            printf("RSA private key n:%d,e:%d,d:%d\r\n",nSize,eSize,dSize);
#endif
            Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+nSize+eSize+dSize);
            uint8_t* data=payload.Data();
            service.srvId=HSE_SRV_ID_IMPORT_KEY;
            service.hseSrv.importKeyReq.cipher.cipherKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.keyContainer.authKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.pKeyInfo=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
            service.hseSrv.importKeyReq.keyLen[0]=nSize;
            service.hseSrv.importKeyReq.pKey[0]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t));
            service.hseSrv.importKeyReq.keyLen[1]=eSize;
            service.hseSrv.importKeyReq.pKey[1]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+nSize);
            service.hseSrv.importKeyReq.keyLen[2]=dSize;
            service.hseSrv.importKeyReq.pKey[2]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+nSize+eSize);
            service.hseSrv.importKeyReq.targetKeyHandle=(hseKeyHandle_t)keyHandle;
            memcpy(data,&service,sizeof(hseSrvDescriptor_t));
            data+=sizeof(hseSrvDescriptor_t);
            memcpy(data,&keyInfo,sizeof(hseKeyInfo_t));
            data+=sizeof(hseKeyInfo_t);
            BN_bn2bin(RSA_get0_n(rsaKey),data);
            data+=nSize;
            BN_bn2bin(RSA_get0_e(rsaKey),data);
            data+=eSize;
            BN_bn2bin(RSA_get0_d(rsaKey),data);
            ret.Set("err",0);
            ret.Set("data",payload);
            ret.Set("msg","successful");
            RSA_free(rsaKey);

        }else if(EVP_PKEY_base_id(evpKey)==EVP_PKEY_EC){
            EC_KEY* ec=EVP_PKEY_get1_EC_KEY(evpKey);
            const EC_GROUP* group=EC_KEY_get0_group(ec);
            int curveId=EC_GROUP_get_curve_name(group);
            keyInfo.specific.eccCurveId=getCurveId(curveId);
            if(keyInfo.specific.eccCurveId!=HSE_EC_CURVE_NONE){
                const BIGNUM* ecPrv=EC_KEY_get0_private_key(ec);
                int dSize=BN_num_bytes(ecPrv);
                const EC_POINT* ecPubPoint=EC_KEY_get0_public_key(ec);
                uint8_t* pubValue;
                //need remove first byte 0x04
                size_t pubSize=EC_POINT_point2buf(group,ecPubPoint,POINT_CONVERSION_UNCOMPRESSED,&pubValue,NULL)-1;
                Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+dSize+pubSize);
                uint8_t* data=payload.Data();
                service.srvId=HSE_SRV_ID_IMPORT_KEY;
                service.hseSrv.importKeyReq.cipher.cipherKeyHandle= HSE_INVALID_KEY_HANDLE;
                service.hseSrv.importKeyReq.keyContainer.authKeyHandle= HSE_INVALID_KEY_HANDLE;
                service.hseSrv.importKeyReq.pKeyInfo=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
                service.hseSrv.importKeyReq.keyLen[0]=pubSize;
                service.hseSrv.importKeyReq.pKey[0]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t));
                service.hseSrv.importKeyReq.keyLen[2]=dSize;
                service.hseSrv.importKeyReq.pKey[2]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+pubSize);
                service.hseSrv.importKeyReq.targetKeyHandle=(hseKeyHandle_t)keyHandle;
                memcpy(data,&service,sizeof(hseSrvDescriptor_t));
                data+=sizeof(hseSrvDescriptor_t);
                memcpy(data,&keyInfo,sizeof(hseKeyInfo_t));
                data+=sizeof(hseKeyInfo_t);
                memcpy(data,pubValue+1,pubSize);
                OPENSSL_free(pubValue);
                data+=pubSize;
                BN_bn2bin(ecPrv,data);
                ret.Set("err",0);
                ret.Set("data",payload);
                ret.Set("msg","successful");
               
            }else{
                ret.Set("err",-1);
                ret.Set("data",Napi::Buffer<uint8_t>::New(info.Env(),0));
                ret.Set("msg","EC unsupport curve id");
            }
            EC_KEY_free(ec);

        }else if(EVP_PKEY_base_id(evpKey)==EVP_PKEY_ED25519){
            //the get value from api is 253;
            keyInfo.keyBitLen=256;
            DSA* dsa=EVP_PKEY_get1_DSA(evpKey);
            keyInfo.specific.eccCurveId=HSE_EC_25519_ED25519;
            uint8_t buf[32];
            size_t len=32;
            /*ed25519 is little endian*/
            EVP_PKEY_get_raw_public_key(evpKey,buf,&len);
            BIGNUM* pubKey=BN_lebin2bn(buf,len,NULL);
            EVP_PKEY_get_raw_private_key(evpKey,buf,&len);
            BIGNUM* prvKey=BN_lebin2bn(buf,len,NULL);
            // for(int i=0;i<8;i++){
            //     printf("0x%x:0x%x,0x%x,0x%x\r\n",buf[i*4+0],buf[i*4+1],buf[i*4+2],buf[i*4+3]);
            // }
            Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+64);
            uint8_t* data=payload.Data();
            service.srvId=HSE_SRV_ID_IMPORT_KEY;
            service.hseSrv.importKeyReq.cipher.cipherKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.keyContainer.authKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.pKeyInfo=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
            service.hseSrv.importKeyReq.keyLen[0]=32;
            service.hseSrv.importKeyReq.pKey[0]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t));
            service.hseSrv.importKeyReq.keyLen[2]=32;
            service.hseSrv.importKeyReq.pKey[2]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+32);
            service.hseSrv.importKeyReq.targetKeyHandle=(hseKeyHandle_t)keyHandle;
            memcpy(data,&service,sizeof(hseSrvDescriptor_t));
            data+=sizeof(hseSrvDescriptor_t);
            memcpy(data,&keyInfo,sizeof(hseKeyInfo_t));
            data+=sizeof(hseKeyInfo_t);
            BN_bn2bin(pubKey,data);
            data+=32;
            BN_bn2bin(prvKey,data);
            BN_free(pubKey);
            BN_free(prvKey);
            ret.Set("err",0);
            ret.Set("data",payload);
            ret.Set("msg","successful");
        }else{
            //TODO
#ifdef DEBUG
            printf("pem type:%d\r\n",EVP_PKEY_base_id(evpKey));
#endif
            ret.Set("err",-1);
            ret.Set("data",Napi::Buffer<uint8_t>::New(info.Env(),0));
            ret.Set("msg","unsupport pem key type");
        }
        EVP_PKEY_free(evpKey);
    }else{
        unsigned long err=ERR_get_error();
        ret.Set("err",err);
        ret.Set("data",Napi::Buffer<uint8_t>::New(info.Env(),0));
        char* errMsg=getErrorMsg(err);
        ret.Set("msg",errMsg);
        delete errMsg;
    }
    BIO_free(keyMem);
    // CRYPTO_mem_leaks_cb(openssl_mem_leak_cb,NULL);
    return ret;
}
Napi::Value HSE::importPubKey(const Napi::CallbackInfo& info){
    hseSrvDescriptor_t service;
    hseKeyInfo_t keyInfo;

    memset((void*)&service,0,sizeof(hseSrvDescriptor_t));
    memset((void*)&keyInfo,0,sizeof(hseKeyInfo_t));
    Napi::Object ret=Napi::Object::New(info.Env());

    uint32_t offset=info[0].As<Napi::Number>().Uint32Value();
    hseKeyHandle_t keyHandle=info[1].As<Napi::Number>().Uint32Value();
    Napi::Object i=info[2].As<Napi::Object>();
    
    keyInfo.keyFlags=i.Get("keyFlags").ToNumber().Uint32Value();
    keyInfo.keyCounter=i.Get("keyCounter").ToNumber().Uint32Value();
    keyInfo.smrFlags=i.Get("smrFlags").ToNumber().Uint32Value();
    keyInfo.keyType=i.Get("keyType").ToNumber().Uint32Value();

    if(i.Has("keyBitLen")){
        keyInfo.keyBitLen=i.Get("keyBitLen").ToNumber().Uint32Value();
    }else{
        keyInfo.keyBitLen=0;
    }

    std::string key=info[3].As<Napi::String>();
    BIO *keyMem = BIO_new_mem_buf(key.c_str(), -1);
    EVP_PKEY* evpKey;
    evpKey=PEM_read_bio_PUBKEY(keyMem,NULL,NULL,NULL);
    if(evpKey!=NULL){
        if(keyInfo.keyBitLen==0){
            keyInfo.keyBitLen=EVP_PKEY_bits(evpKey);
        }
#ifdef DEBUG
        printf("key bit len %d\r\n",keyInfo.keyBitLen);
#endif
        if(EVP_PKEY_base_id(evpKey)==EVP_PKEY_RSA){
            RSA* rsaKey=EVP_PKEY_get1_RSA(evpKey);
            keyInfo.specific.pubExponentSize=BN_num_bytes(RSA_get0_e(rsaKey));
            int nSize=BN_num_bytes(RSA_get0_n(rsaKey));
            int eSize=BN_num_bytes(RSA_get0_e(rsaKey));
#ifdef DEBUG
            printf("RSA pub key n:%d,e:%d\r\n",nSize,eSize);
#endif
            Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+nSize+eSize);
            uint8_t* data=payload.Data();
            service.srvId=HSE_SRV_ID_IMPORT_KEY;
            service.hseSrv.importKeyReq.cipher.cipherKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.keyContainer.authKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.pKeyInfo=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
            service.hseSrv.importKeyReq.keyLen[0]=nSize;
            service.hseSrv.importKeyReq.pKey[0]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t));
            service.hseSrv.importKeyReq.keyLen[1]=eSize;
            service.hseSrv.importKeyReq.pKey[1]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+nSize);
            service.hseSrv.importKeyReq.targetKeyHandle=(hseKeyHandle_t)keyHandle;
            memcpy(data,&service,sizeof(hseSrvDescriptor_t));
            data+=sizeof(hseSrvDescriptor_t);
            memcpy(data,&keyInfo,sizeof(hseKeyInfo_t));
            data+=sizeof(hseKeyInfo_t);
            BN_bn2bin(RSA_get0_n(rsaKey),data);
            data+=nSize;
            BN_bn2bin(RSA_get0_e(rsaKey),data);
            ret.Set("err",0);
            ret.Set("data",payload);
            ret.Set("msg","successful");
            RSA_free(rsaKey);

        }else if(EVP_PKEY_base_id(evpKey)==EVP_PKEY_EC){
            EC_KEY* ec=EVP_PKEY_get1_EC_KEY(evpKey);
            const EC_GROUP* group=EC_KEY_get0_group(ec);
            int curveId=EC_GROUP_get_curve_name(group);
            keyInfo.specific.eccCurveId=getCurveId(curveId);
            if(keyInfo.specific.eccCurveId!=HSE_EC_CURVE_NONE){
                const EC_POINT* ecPubPoint=EC_KEY_get0_public_key(ec);
                uint8_t* pubValue;
                //need remove first byte 0x04
                size_t pubSize=EC_POINT_point2buf(group,ecPubPoint,POINT_CONVERSION_UNCOMPRESSED,&pubValue,NULL)-1;
                Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+pubSize);
                uint8_t* data=payload.Data();
                service.srvId=HSE_SRV_ID_IMPORT_KEY;
                service.hseSrv.importKeyReq.cipher.cipherKeyHandle= HSE_INVALID_KEY_HANDLE;
                service.hseSrv.importKeyReq.keyContainer.authKeyHandle= HSE_INVALID_KEY_HANDLE;
                service.hseSrv.importKeyReq.pKeyInfo=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
                service.hseSrv.importKeyReq.keyLen[0]=pubSize;
                service.hseSrv.importKeyReq.pKey[0]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t));
                service.hseSrv.importKeyReq.targetKeyHandle=(hseKeyHandle_t)keyHandle;
                memcpy(data,&service,sizeof(hseSrvDescriptor_t));
                data+=sizeof(hseSrvDescriptor_t);
                memcpy(data,&keyInfo,sizeof(hseKeyInfo_t));
                data+=sizeof(hseKeyInfo_t);
                memcpy(data,pubValue+1,pubSize);
                OPENSSL_free(pubValue);
                ret.Set("err",0);
                ret.Set("data",payload);
                ret.Set("msg","successful");
               
            }else{
                ret.Set("err",-1);
                ret.Set("data",Napi::Buffer<uint8_t>::New(info.Env(),0));
                ret.Set("msg","EC unsupport curve id");
            }
            EC_KEY_free(ec);

        }else if(EVP_PKEY_base_id(evpKey)==EVP_PKEY_ED25519){
            //the get value from api is 253;
            keyInfo.keyBitLen=256;
            DSA* dsa=EVP_PKEY_get1_DSA(evpKey);
            keyInfo.specific.eccCurveId=HSE_EC_25519_ED25519;
            uint8_t buf[32];
            size_t len=32;
            /*ed25519 is little endian*/
            EVP_PKEY_get_raw_public_key(evpKey,buf,&len);
            BIGNUM* pubKey=BN_lebin2bn(buf,len,NULL);
            Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+32);
            uint8_t* data=payload.Data();
            service.srvId=HSE_SRV_ID_IMPORT_KEY;
            service.hseSrv.importKeyReq.cipher.cipherKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.keyContainer.authKeyHandle= HSE_INVALID_KEY_HANDLE;
            service.hseSrv.importKeyReq.pKeyInfo=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
            service.hseSrv.importKeyReq.keyLen[0]=32;
            service.hseSrv.importKeyReq.pKey[0]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t));
            service.hseSrv.importKeyReq.targetKeyHandle=(hseKeyHandle_t)keyHandle;
            memcpy(data,&service,sizeof(hseSrvDescriptor_t));
            data+=sizeof(hseSrvDescriptor_t);
            memcpy(data,&keyInfo,sizeof(hseKeyInfo_t));
            data+=sizeof(hseKeyInfo_t);
            BN_bn2bin(pubKey,data);
            data+=32;
            BN_free(pubKey);
            ret.Set("err",0);
            ret.Set("data",payload);
            ret.Set("msg","successful");
        }else{
            //TODO
#ifdef DEBUG
            printf("pem type:%d\r\n",EVP_PKEY_base_id(evpKey));
#endif
            ret.Set("err",-1);
            ret.Set("data",Napi::Buffer<uint8_t>::New(info.Env(),0));
            ret.Set("msg","unsupport pem key type");
        }
        EVP_PKEY_free(evpKey);
    }else{
        unsigned long err=ERR_get_error();
        ret.Set("err",err);
        ret.Set("data",Napi::Buffer<uint8_t>::New(info.Env(),0));
        char* errMsg=getErrorMsg(err);
        ret.Set("msg",errMsg);
        delete errMsg;
    }
    BIO_free(keyMem);
    // CRYPTO_mem_leaks_cb(openssl_mem_leak_cb,NULL);
    return ret;
}
Napi::Value HSE::formatCatalog(const Napi::CallbackInfo& info){
    hseSrvDescriptor_t service;
    memset((void*)&service,0,sizeof(hseSrvDescriptor_t));
    Napi::Object ret=Napi::Object::New(info.Env());
    uint32_t offset=info[0].As<Napi::Number>().Uint32Value();
    Napi::Array nvm= info[1].As<Napi::Array>();
    Napi::Array ram= info[2].As<Napi::Array>();

    uint32_t nvmLen= nvm.Length();
    uint32_t ramLen= ram.Length();
    
    hseKeyGroupCfgEntry_t* nvmCat = new hseKeyGroupCfgEntry_t[nvmLen];
    hseKeyGroupCfgEntry_t* ramCat = new hseKeyGroupCfgEntry_t[ramLen];

    for(uint32_t i=0;i<nvmLen;i++){
        Napi::Value v=nvm[i];
        nvmCat[i].groupOwner=v.ToObject().Get("groupOwner").ToNumber().Uint32Value();
        nvmCat[i].keyType=v.ToObject().Get("keyType").ToNumber().Uint32Value();
        nvmCat[i].maxKeyBitLen=v.ToObject().Get("maxKeyBitLen").ToNumber().Uint32Value();
        nvmCat[i].muMask=v.ToObject().Get("muMask").ToNumber().Uint32Value();
        nvmCat[i].numOfKeySlots=v.ToObject().Get("numOfKeySlots").ToNumber().Uint32Value();
        nvmCat[i].hseReserved[0]=0;
        nvmCat[i].hseReserved[1]=0;
    } 
    for(uint32_t i=0;i<ramLen;i++){
        Napi::Value v=ram[i];
        ramCat[i].groupOwner=v.ToObject().Get("groupOwner").ToNumber().Uint32Value();
        ramCat[i].keyType=v.ToObject().Get("keyType").ToNumber().Uint32Value();
        ramCat[i].maxKeyBitLen=v.ToObject().Get("maxKeyBitLen").ToNumber().Uint32Value();
        ramCat[i].muMask=v.ToObject().Get("muMask").ToNumber().Uint32Value();
        ramCat[i].numOfKeySlots=v.ToObject().Get("numOfKeySlots").ToNumber().Uint32Value();
        ramCat[i].hseReserved[0]=0;
        ramCat[i].hseReserved[1]=0;
    } 

    Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyGroupCfgEntry_t)*nvmLen+sizeof(hseKeyGroupCfgEntry_t)*ramLen);
    uint8_t* data=payload.Data();
    service.srvId=HSE_SRV_ID_FORMAT_KEY_CATALOGS;
    service.hseSrv.formatKeyCatalogsReq.pNvmKeyCatalogCfg= (HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
    service.hseSrv.formatKeyCatalogsReq.pRamKeyCatalogCfg= (HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyGroupCfgEntry_t)*nvmLen);
    memcpy(data,&service,sizeof(hseSrvDescriptor_t));
    data+=sizeof(hseSrvDescriptor_t);
    memcpy(data,nvmCat,sizeof(hseKeyGroupCfgEntry_t)*nvmLen);
    data+=sizeof(hseKeyGroupCfgEntry_t)*nvmLen;
    memcpy(data,ramCat,sizeof(hseKeyGroupCfgEntry_t)*ramLen);
    delete nvmCat;
    delete ramCat;
    
    ret.Set("err",0);
    ret.Set("data",payload);
    ret.Set("msg","successful");
    
    return ret;
}

Napi::Value HSE::importSymKey(const Napi::CallbackInfo& info){
    hseSrvDescriptor_t service;
    hseKeyInfo_t keyInfo;

    memset((void*)&service,0,sizeof(hseSrvDescriptor_t));
    memset((void*)&keyInfo,0,sizeof(hseKeyInfo_t));
    Napi::Object ret=Napi::Object::New(info.Env());

    uint32_t offset=info[0].As<Napi::Number>().Uint32Value();
    hseKeyHandle_t keyHandle=info[1].As<Napi::Number>().Uint32Value();
    Napi::Object i=info[2].As<Napi::Object>();
    
    keyInfo.keyFlags=i.Get("keyFlags").ToNumber().Uint32Value();
    keyInfo.keyCounter=i.Get("keyCounter").ToNumber().Uint32Value();
    keyInfo.smrFlags=i.Get("smrFlags").ToNumber().Uint32Value();
    keyInfo.keyType=i.Get("keyType").ToNumber().Uint32Value();
    if(i.Has("keyBitLen")){
        keyInfo.keyBitLen=i.Get("keyBitLen").ToNumber().Uint32Value();
    }else{
        keyInfo.keyBitLen=0;
    }

    Napi::Buffer<uint8_t> key=info[3].As<Napi::Buffer<uint8_t>>();
    if(keyInfo.keyBitLen==0){
        keyInfo.keyBitLen=key.Length()*8;
    }
    
  
    Napi::Buffer<uint8_t> payload=Napi::Buffer<uint8_t>::New(info.Env(),sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t)+key.Length());
    uint8_t* data=payload.Data();
    service.srvId=HSE_SRV_ID_IMPORT_KEY;
    service.hseSrv.importKeyReq.cipher.cipherKeyHandle= HSE_INVALID_KEY_HANDLE;
    service.hseSrv.importKeyReq.keyContainer.authKeyHandle= HSE_INVALID_KEY_HANDLE;
    service.hseSrv.importKeyReq.pKeyInfo=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t));
    service.hseSrv.importKeyReq.keyLen[2]=key.Length();
    service.hseSrv.importKeyReq.pKey[2]=(HOST_ADDR)(offset+sizeof(hseSrvDescriptor_t)+sizeof(hseKeyInfo_t));
    service.hseSrv.importKeyReq.targetKeyHandle=(hseKeyHandle_t)keyHandle;
    memcpy(data,&service,sizeof(hseSrvDescriptor_t));
    data+=sizeof(hseSrvDescriptor_t);
    memcpy(data,&keyInfo,sizeof(hseKeyInfo_t));
    data+=sizeof(hseKeyInfo_t);
    memcpy(data,key.Data(),key.Length());

    
    ret.Set("err",0);
    ret.Set("data",payload);
    ret.Set("msg","successful");
    
    return ret;
}




#define DECLARE_NAPI_METHOD(name,func) \
    exports.Set(Napi::String::New(env, name), \
              Napi::Function::New(env, func))

#define DECLARE_NAPI_UINT32(symbol)\
    exports.Set(Napi::String::New(env, #symbol), \
              Napi::Number::New(env, symbol))

#define DECLARE_NAPI_STRING(name,value)\
    exports.Set(Napi::String::New(env, #name), \
              Napi::String::New(env, value))

Napi::Object Init(Napi::Env env, Napi::Object exports) {

    DECLARE_NAPI_UINT32(HSE_MU0_MASK);
    DECLARE_NAPI_UINT32(HSE_MU1_MASK);
    DECLARE_NAPI_UINT32(HSE_MU2_MASK);
    DECLARE_NAPI_UINT32(HSE_MU3_MASK);
    DECLARE_NAPI_UINT32(HSE_ALL_MU_MASK);
    DECLARE_NAPI_UINT32(HSE_APP_CORE0);
    DECLARE_NAPI_UINT32(HSE_APP_CORE1);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_0);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_1);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_2);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_3);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_4);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_5);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_6);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_7);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_8);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_9);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_10);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_11);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_12);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_13);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_14);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_15);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_16);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_17);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_18);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_19);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_20);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_21);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_22);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_23);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_24);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_25);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_26);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_27);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_28);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_29);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_30);
    DECLARE_NAPI_UINT32(HSE_KF_SMR_31);
    DECLARE_NAPI_UINT32(HSE_KEY_CATALOG_ID_ROM);
    DECLARE_NAPI_UINT32(HSE_KEY_CATALOG_ID_NVM);
    DECLARE_NAPI_UINT32(HSE_KEY_CATALOG_ID_RAM);
    DECLARE_NAPI_UINT32(HSE_KEY_OWNER_ANY);
    DECLARE_NAPI_UINT32(HSE_KEY_OWNER_CUST);
    DECLARE_NAPI_UINT32(HSE_KEY_OWNER_OEM);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_SHE);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_AES);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_HMAC);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_TDES);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_SHARED_SECRET);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_ECC_PAIR);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_ECC_PUB);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_ECC_PUB_EXT);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_RSA_PAIR);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_RSA_PUB);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_RSA_PUB_EXT);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_DH_PAIR);
    DECLARE_NAPI_UINT32(HSE_KEY_TYPE_DH_PUB);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_ENCRYPT);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_DECRYPT);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_SIGN);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_VERIFY);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_EXCHANGE);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_DERIVE);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_KEY_PROVISION);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_AUTHORIZATION);
    DECLARE_NAPI_UINT32(HSE_KF_ACCESS_WRITE_PROT);
    DECLARE_NAPI_UINT32(HSE_KF_ACCESS_DEBUG_PROT);
    DECLARE_NAPI_UINT32(HSE_KF_ACCESS_EXPORTABLE);
    DECLARE_NAPI_UINT32(HSE_KF_USAGE_MASK);
    DECLARE_NAPI_UINT32(HSE_KF_ACCESS_MASK);
    DECLARE_NAPI_UINT32(HSE_ROM_KEY_AES256_KEY0);
    DECLARE_NAPI_UINT32(HSE_ROM_KEY_AES256_KEY1);
    DECLARE_NAPI_UINT32(HSE_ROM_KEY_RSA2048_PUB_KEY2);
    DECLARE_NAPI_UINT32(HSE_ROM_KEY_ECC256_PUB_KEY3);
    DECLARE_NAPI_UINT32(HSE_KEY_BITS_INVALID);
    DECLARE_NAPI_UINT32(HSE_KEY_BITS_ZERO);
    DECLARE_NAPI_UINT32(HSE_KEY128_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY160_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY192_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY224_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY240_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY256_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY320_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY384_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY512_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY521_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY638_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY1024_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY2048_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY3072_BITS);
    DECLARE_NAPI_UINT32(HSE_KEY4096_BITS);
    exports=HSE::Init(env,exports);
    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
