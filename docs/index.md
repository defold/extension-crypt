---
title: Defold Crypt documentation
brief: This manual covers how to use various hashing and encoding algorithms in Defold.
---

# Defold Crypt documentation
This extension provides functions for interacting with various hash and encode/decode algorithms. The extension wraps the [dmCrypt API](https://defold.com/ref/stable/dmCrypt/) from the Defold SDK to Lua.


## Installation
To use this library in your Defold project, add the following URL to your `game.project` dependencies:

https://github.com/defold/extension-crypt/archive/master.zip

We recommend using a link to a zip file of a [specific release](https://github.com/defold/extension-crypt/releases).


## Usage

The API provides the following functions:

* `crypt.encode_base64(source)`
* `crypt.decode_base64(source)`
* `crypt.hash_sha256(source)`


## Source code

The source code is available on [GitHub](https://github.com/defold/extension-crypt)


## API reference
