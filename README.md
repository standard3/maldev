# maldev

My malware developpement exercices / experiments primarly in Rust, cross-compiled from Linux

## Cross-compiling

To build the project on Linux, follow these instructions. You have to install MSVC.

```shell
$ rustup target add x86_64-pc-windows-msvc
# add target for each build
$ cargo build --target x86_64-pc-windows-msvc ...
```

## Available features

### Payload Placement

```shell
$ cargo build --features payloadplacement
```
