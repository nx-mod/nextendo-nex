# nextendo-nex (nx-mod testing)

nx-mod's `testing` fork of [nextendo-nex](https://github.com/NextendoNetwork/nextendo-nex): From-scratch Go implementation of Nintendo's NEX/PRUDP protocol: the Nextendo Network server core.
Part of [nextendo-testing](https://github.com/nx-mod/nextendo-testing): the whole Nextendo Network, run on a LAN. Upstream's README is kept as [README.upstream.md](README.upstream.md).

## nx-mod changes

- Eagle relay protocol (Super Mario Bros. 35, Tetris 99, PAC-MAN 99, F-Zero 99).
- Ranking: `UploadScore` (lenient decode), `GetRanking`, `GetCachedTopXRanking`.
- Monster Hunter Generations Ultimate support; the observed endpoint is used when a client reports a VPN adapter address; a connection's WebSocket frames are processed in order.

## Credits

nextendo-nex is the work of the **Nextendo Network team** — https://nextendo.network. nx-mod only adds the changes above, for LAN testing. Nextendo is awesome.
