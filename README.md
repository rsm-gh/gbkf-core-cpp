
C++ implementation of the [Generic Binary Keyed Format (*.gbkf)](https://gbkf-format.org).

## Implementation Remarks

+ The current supported string encodings are `ASCII`, `Latin-1` and `UTF-8`.

+ In some cases method overloading was avoided because:
  + It makes explicit for the developer the type of the data is being handled, which I think it's a very important detail in a binary format.
  + It will harmonize the implementation across different languages.

  An example of this is `addKeyedValuesUInt8`, `addKeyedValuesUInt16`, ...

+ `KeyedEntry` was moved into a class to enforce the safety of casting the shared pointer of the values.