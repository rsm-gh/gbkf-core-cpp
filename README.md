
C++ implementation of the [Generic Binary Keyed Format (*.gbkf)](https://gbkf-format.org).

## Remarks

+ This implementation only supports CPUs that use little-endian byte order. If the CPU uses a different byte order, the Reader and Writer constructors will throw an exception. You can create a ticket if needed.

+ Currently, the Reader and Writer classes store all content in RAM. In the future, they will be improved to support disk-based I/O operations for large files.

+ In some cases method overloading was avoided because:
  + It makes explicit for the developer the type of the data is being handled, which I think it's a very important detail in a binary format.
  + It will harmonize the implementation across different languages.

  An example of this is `addKeyedValuesUInt8`, `addKeyedValuesUInt16`, ...

+ `KeyedEntry` was moved into a class to enforce the safety of casting the shared pointer of the values.