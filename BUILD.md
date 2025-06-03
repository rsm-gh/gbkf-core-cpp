
## Cmake
```
cmake -DCMAKE_BUILD_TYPE=Release ..
make
make install
```

Use the flag `cmake .. -DCMAKE_INSTALL_PREFIX=/usr` to install it into the system's directory and make it detectable
by default without adding it into the `ldconfig` path.

## Emscripten
```
emcmake cmake -DCMAKE_BUILD_TYPE=Release ..
emmake make
```


## OpenSSL

By default, [PicoSha2](https://github.com/okdshin/PicoSHA2/blob/master/picosha2.h) will be used to compute the SHA256.
If instead you want to use OpenSSL, install it (`apt-get install libssl-dev`) and use the following flag: `-DUSE_OPEN_SSL=ON`.

Note: PicoSha2 was particularly added to simplify the static/emscripten build.