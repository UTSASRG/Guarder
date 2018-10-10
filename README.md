# Guarder

#### Compilation
Simply use `make clean; make` to compile the allocator. This will produce a DSO named `libguarder.so` which may then be linked to applications at compile-time using the `-rdynamic /path/to/libguarder.so` flag.

To link to an existing, pre-compiled application, utilize the `LD_PRELOAD` environment variable when executing the program. For example: `$ LD_PRELOAD=/path/to/libguarder.so ./program-to-run`.
