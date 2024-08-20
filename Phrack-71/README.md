This article was published in [Phrack Issue 71](http://www.phrack.org/issues/71/1.html)

- [article](http://www.phrack.org/issues/71/11.html#article)
- [Caesar source code, in Dart](./phrack.dart), [similar source code in C](./phrack.c)
- [Dart AOT snapshot](./phrack.aot)
- [Non stripped AOT snapshot](./phrack.aot.notstripped)


**Notes / Erratum:**

- Section 1.4: at the time of writing the article, Dart was pushing all arguments on the stack. [Since Dart v3.4.0, this is no longer true, and Dart uses specific registers to pass arguments](https://cryptax.medium.com/dart-shifts-to-standard-calling-convention-26dc65f8d15a). This is actually a more standard calling convention.
- Section 3: The content r14 + 0x68 is slightly uncertain, due to changes in the Dart SDK and lack of documentation. It is likely *not the null object* but an offset to Dart's global field table values.
