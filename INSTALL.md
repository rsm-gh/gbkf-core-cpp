
<!-- Install OpenSSL DEV: Replaced with picosha2.hxx to compile more easily with emscripten
```
apt-get install libssl-dev
``` -->


To install the library in the system, use:
```
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
make install
ldconfig
```

otherwise, it will be installed under `/usr/include` and by default the path is not added into ldconfig.


Compile with emscripten:
```
emcmake cmake -DBUILD_SHARED_LIBS=OFF ..
emmake make
```
