# Simple Linear Sweep for BinaryNinja
Author: **butters**

_A simple linear sweep for x86 and x86_64._

## Description:

This plugin is a temporary solution until a linear sweep is included in core. It identifies functions by searching for common prologues and makes an attempt to avoid some false positives by analysing the created function. 

To install this plugin, navigate to your Binary Ninja plugins directory, and run

```git clone https://github.com/lstotch/binaryninja-linsweep.git linsweep```

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release (Commercial) - 1.0.729-dev
 * release (Personal) - 1.0.729-dev

## License

This plugin is released under a [MIT](LICENSE) license.

