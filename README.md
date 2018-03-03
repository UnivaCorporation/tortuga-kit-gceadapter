# tortuga-kit-gceadapter

## Overview

This repository contains the requisite files to build a resource adapter kit to
enable support for [Google Compute Engine](https://cloud.google.com/compute/)
compute nodes in [Tortuga][].

## Building the kit

Change to subdirectory containing cloned Git repository and run `build-kit`.
`build-kit` is provided by the `tortuga-core` package in the [Tortuga][]
source.

## Installation

Install the kit:

```shell
install-kit kit-gceadapter*.tar.bz2
```

See the [Tortuga Installation and Administration Guide](https://github.com/UnivaCorporation/tortuga/blob/master/doc/tortuga-6-admin-guide.md) for configuration
details.

[Tortuga]: https://github.com/UnivaCorporation/tortuga "Tortuga"
