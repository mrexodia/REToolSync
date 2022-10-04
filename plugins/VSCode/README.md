# REToolSync

This is an extension that improves your reverse engineering workflow using [REToolSync](https://github.com/mrexodia/REToolSync).

## Features

If you print an address `0x12345` in the Terminal you can use Ctrl+Click to follow that address in all REToolSync-supported tools.

## Development

```
# Global dependencies
npm i -g vsce yo generator-code
# Local dependencies
npm i
# Build VSIX
vsce package
```