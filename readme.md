# 💚 Session chat vanity address generator

Allows to generate public addresses with custom prefix which consists of a specified number of selected byte value

## Installation:

`git clone https://github.com/zeokku/session-vanity-generator.git`

`cd session-vanity-generator`

`pnpm i`

## Usage

`pnpm run dry [PREFIX] [SEED_LENGTH]`

Both arguments are optional.

The default prefix is `"1234"`.

Default seed length is `16`. The seed length must be divisible by 4. Currently at least iOS app doesn't support longer mnemonic phrases than 13 words (corresponds to the default seed length). So unless you know what you're doing, it's advised not to touch the seed length parameter.

### Example:

`pnpm run dry 1248 32`

Technically you can run multiple instances to simulate multithreading and thus speed up the brute force.

## Warning:

If you choose a prefix length of more than a few characters, you may die before the program finishes executing.
