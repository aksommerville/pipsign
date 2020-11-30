# pipsign

Utility to sign a Pippin disc as if by Apple.

Requires bash and python.

Requires [Retro68](https://github.com/autc04/Retro68) unless you are providing your own HFS images.

Usage: `./pipsign.sh MY_INPUT_DIRECTORY MY_OUTPUT_DISC_IMAGE`

Or with bootable HFS image: `./pipsign.py MY_HFS_IMAGE MY_OUTPUT_DISC_IMAGE`

Or to verify a signed image: `./pipsign.py IMAGE`
