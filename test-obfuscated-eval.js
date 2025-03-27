// Test obfuscated eval usage
function executeExpression(expr) {
  window["\\x65\\x76\\x61\\x6c"](expr);
}

// Test for obfuscated eval - string concatenation
function exec(code) {
  window["\\x65" + "\\x76" + "\\x61" + "\\x6c"](code);
}

// Testing with eval hidden in array
function _0x4a92(_0x171a,_0x3fb5){
  const _0x1e87=["eval","parse","log","2523048bLmURU","1013452SgGzcv","9CUthji",
  "308930hKWeQm","1882730MqMhFH","1391616gLGduU","45LTxKUK","6KTnehM","10ymCHOR","test","188090hPJEZd"];
  _0x4a92=function(){return _0x1e87;};
  return _0x4a92();
}

function _0x1c68(_0x171a56,_0x44c83b){
  const _0x4a92a1=_0x4a92();
  return _0x1c68=function(_0x1c6888,_0x57e47d){
    _0x1c6888=_0x1c6888-0x1e4;
    let _0x5d505c=_0x4a92a1[_0x1c6888];
    return _0x5d505c;
  },
  _0x1c68(_0x171a56,_0x44c83b);
}

// Should detect these as malicious
executeExpression("alert(1)");
exec("console.log('test')");