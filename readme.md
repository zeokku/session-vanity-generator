# 💚 Session chat vanity address generator

Allows to generate public addresses with custom prefix which consists of a specified number of selected byte value

## Installation:

`pnpm i`

## Usage

`pnpm run dry [BYTE_VALUE] [SEED_LENGTH]`

Both arguments are optional.

Default byte value is `"55"`.

Default seed length is `16`. The seed length must be divisible by 4. Currently at least iOS app doesn't support longer mnemonic phrases than 13 words (corresponds to the default seed length). So unless you know what you're doing, it's advised not to touch the seed length parameter.

### Example:

`pnpm run dry 00`
