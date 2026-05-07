# Waterwall 

![GitHub commit activity](https://img.shields.io/github/commit-activity/m/radkesvat/WaterWall)
[![CLang Static Analyzer](https://github.com/radkesvat/WaterWall/actions/workflows/clang_static_analyzer.yml/badge.svg)](https://github.com/radkesvat/WaterWall/actions/workflows/clang_static_analyzer.yml)

[![CI](https://github.com/radkesvat/WaterWall/actions/workflows/ci.yaml/badge.svg)](https://github.com/radkesvat/WaterWall/actions/workflows/ci.yaml)



## Overview

A simple networking core for tunneling and direct user–server connections.
Built on high-performance, fully customizable nodes, it allows you to create a wide range of protocols without writing low-level implementation code.
*(Though admittedly, it might make things feel more complex depending on how you use it.)*

## Getting Started

To begin, please read the documentation:
👉 [https://radkesvat.github.io/WaterWall-Docs/](https://radkesvat.github.io/WaterWall-Docs/)

> **Note:** The documentation is currently available only in Persian.

## Additional Documentation

If you're familiar with network protocol structures:

* Each tunnel includes a `description.md` file
* These files are written in English
* They provide advanced documentation and implementation details

## Quick Build (Fresh Ubuntu / Generic Linux VPS)

You can build **WaterWall** on a fresh Ubuntu (or most Debian-based) VPS with just two commands:

```bash
apt-get purge -y cmake; apt-get update; apt-get install -y snapd build-essential ninja-build ccache; snap install cmake --classic
```

```bash
git clone https://github.com/radkesvat/WaterWall && cd WaterWall && cmake --preset linux-gcc-x64 && cmake --build --preset linux-gcc-x64
```

This will install all required dependencies, fetch the project, and compile it using the provided CMake presets.

> **Note:** The first command ensures a modern version of CMake via `snap`, which is required for the preset-based build system.


## Questions & Suggestions

Feel free to reach out in my small [Telegram group](https://t.me/radkesvat_group) if you have any questions about this project, networking, or programming in general. I’m also happy to hear your suggestions and feedback!

<!-- # Plan

- [x] Restructure the project into a much cleaner design  
- [ ] Remove OpenSSL/WolfSSL client, create a TLS client using curl-impersonate  
- [ ] Rework OpenSSL server, configure options to match Nginx identically  
- [ ] Focus on HTTP/1 or HTTP/2, make every option configurable via JSON  
- [ ] Redesign Layer 3 nodes with a different architecture  
- [x] Add support for WireGuard  
- [ ] Add support for Router  
- [ ] Implement more transports like HTTP/3 or a stream control node  
 -->
<!-- 


Thanks for the support! ❤ -->

