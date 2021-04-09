const HSEnode = require('./build/Release/HSE.node')
class HSE extends HSEnode.HSE{
    constructor(){
        super()
    }
    GET_CATALOG_ID(keyHandle){
        return ((keyHandle>>16)&0xff)
    }
    GET_GROUP_IDX(keyHandle){
        return ((keyHandle>>8)&0xff)
    }
    GET_SLOT_IDX(keyHandle){
        return (keyHandle&0xff)
    }
    GET_KEY_HANDLE(catalog,group,slot){
        return ((catalog&0xff)<<16)|((group&0xff)<<8)|(slot&0xff)
    }

}
module.exports = new HSE()