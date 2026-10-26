{
  'targets': [
    {
      'target_name': 'capnp',
      'sources': ['src/node-capnp/capnp.cc'],
      'cflags_cc': ['-std=c++20'],
      'cflags_cc!': ['-fno-rtti', '-fno-exceptions'],
      'include_dirs': [
        'src',
        '<!(node -e "require(\'nan\')")'
      ],
      'conditions': [
        [ 'OS=="mac"', {
          # TODO: Does this condition actually get picked up when we're cross-compiling to Darwin?
          # Experimenting with Win32 cross-compilation suggests `OS` is still set to `linux`.

          'xcode_settings': {
            'OTHER_CPLUSPLUSFLAGS' : ['-std=c++20','-stdlib=libc++'],
            'OTHER_LDFLAGS': ['-stdlib=libc++'],
            'GCC_ENABLE_CPP_RTTI': 'YES',
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
            'MACOSX_DEPLOYMENT_TARGET': '13.0'
          },

          # Dynamic linking
          'libraries': [
            '-lkj', '-lkj-async', '-lcapnp', '-lcapnpc', '-lcapnp-rpc',
          ]
        }],
        [ 'OS=="linux"', {

          # Static linking
          'libraries': [
            # The --whole-archive flag is conventional when composing a shared library from static
            # libraries, to ensure that no parts of the static libraries are omitted.
            '-Wl,--whole-archive',
            '../build-capnp/.libs/libkj.a',
            '../build-capnp/.libs/libkj-async.a',
            '../build-capnp/.libs/libcapnp.a',
            '../build-capnp/.libs/libcapnpc.a',
            '../build-capnp/.libs/libcapnp-rpc.a',
            '-Wl,--no-whole-archive',
          ],
        }],
        [ 'OS=="win"', {
          # capnp.cc expects RTTI and exceptions to be enabled, but gyp disables them by default
          'msvs_settings': {
            'VCCLCompilerTool': {
              'ExceptionHandling': 1,
              'RuntimeTypeInfo': 'true',
              'AdditionalOptions': ['/GR'],
            }
          },

          # Static linking
          'libraries': [
            'ws2_32.lib', 'kj.lib', 'kj-async.lib', 'capnp.lib', 'capnpc.lib', 'capnp-rpc.lib',
          ]
        }],
      ],

    }
  ]
}
