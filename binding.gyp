{
  "targets": [
    {
      "target_name": "HSE",
      "sources": [ "hse/hse_napi.cpp" ],
      "include_dirs": ["hse/include","hse/include/hse_header","hse/include/hse_header/hse_common",
                      "hse/include/hse_header/hse_config","hse/include/hse_header/hse_services","<!@(node -p \"require('node-addon-api').include\")"],
      'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS','NAPI_EXPERIMENTAL'],
      'libraries': ['<(module_root_dir)/hse/libcrypto_static.lib']
    }
  ]
}