# maldev

My malware developpement exercices / experiments primarly in Rust, cross-compiled from Linux

## Cross-compiling

To build the project on Linux, follow these instructions. You have to install MSVC.

```shell
$ rustup target add x86_64-pc-windows-msvc
# add target for each build
$ cargo build --target x86_64-pc-windows-msvc ...
```

> [!Note]
> My Nix Flake is private for this repository, if want to use one you can create it and :
> ```
> $ git add --intent-to-add flake.nix
> $ git update-index --assume-unchanged flake.nix
> ```

## Available features

### Payload Placement

```shell
$ cargo build --features payloadplacement
```

## Resources

- [Rust Foreign calling conventions](https://doc.rust-lang.org/nomicon/ffi.html#foreign-calling-conventions)
