The [slides](./Nullcon2024-Apvrille.pdf) were presented at **Nullcon Berlin 2024**.

## Want to try the challenge?

- Get the [Dart AOT snapshot file](./pico.aot) `pico.aot`
- Your goal is to unlock the door of the fridge

```
The door is locked
```

## Run the challenge

### Run the Dart AOT snapshot

- Run it with: `dartaotruntime ./pico.aot`

If you get this error, it's because you don't have the correct runtime version.

```
VM initialization failed: Wrong full snapshot version, expected 'ee1eb666c76a5cb7746faf39d0b97547' found '90b56a561f70cd55e972cb49b79b3d8b'
```

There are 2 solutions:

a) Get the correct runtime :smile:
b) Run from sources (see below)

### Alternative: run from the sources

**SPOILER ALERT**: **do not read** the source file `./pico.dart`! Just *run* from sources. The difficulty of the challenge consists in *reversing a Dart AOT snapshot*. If you read the sources, it's game over :wink:

- [Dart source file (SPOILER)](./pico.dart)
- Running from sources: `dart run pico.dart`

```
$ dart run pico.dart 
====== DART.Y - Your Secure & Smart Fridge ======
Password: 
...
The door is locked
```




