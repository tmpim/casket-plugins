# webdav

> ⚠️ This plugin is no longer maintained, nor is it compatible with casket 2+. For a casket v2 WebDAV plugin, please check [@mholt's webdav plugin](https://github.com/mholt/casket-webdav/).

[![Build](https://img.shields.io/circleci/project/github/emmachase/casket-webdav/master.svg?style=flat-square)](https://circleci.com/gh/emmachase/casket-webdav)
[![community](https://img.shields.io/badge/community-forum-ff69b4.svg?style=flat-square)](https://casket.community)
[![Go Report Card](https://goreportcard.com/badge/github.com/emmachase/casket-webdav?style=flat-square)](https://goreportcard.com/report/emmachase/casket-webdav)

casket plugin that implements WebDAV. You can download this plugin with casket on its [official download page](https://casketserver.com/download).

(Forked from: https://github.com/hacdias/caddy-v1-webdav)

## Syntax

```
webdav [url] {
    scope       path
    modify      [true|false]
    allow       path
    allow_r     regex
    block       path
    block_r     regex
}
```

All the options are optional.

+ **url** is the place where you can access the WebDAV interface. Defaults to `/`.
+ **scope** is an absolute or relative (to the current working directory of casket) path that indicates the scope of the WebDAV. Defaults to `.`.
+ **modify** indicates if the user has permission to edit/modify the files. Defaults to `true`.
+ **allow** and **block** are used to allow or deny access to specific files or directories using their relative path to the scope. You can use the magic word `dotfiles` to allow or deny the access to every file starting by a dot.
+ **allow_r** and **block_r** and variations of the previous options but you are able to use regular expressions with them.

It is highly recommended to use this directive alongside with [`basicauth`](https://caddy.its-em.ma/v1/docs/basicauth) to protect the WebDAV interface.

```
webdav {
    # You set the global configurations here and
    # all the users will inherit them.
    user1:
    # Here you can set specific settings for the 'user1'.
    # They will override the global ones for this specific user.
}
```

## Examples

WebDAV on `/` for the current working directory:

```
webdav
```

WebDAV on `/admin` for the whole file system:

```
webdav /admin {
    scope /
}
```

WebDAV on `/` for the whole file system, without access to `/etc` and `/dev` directories:

```
webdav {
    scope /
    block /etc
    block /dev
}
```

WebDAV on `/` for the whole file system. The user `sam` can't access `/var/www` but the others can.

```
basicauth / sam pass
webdav {
    scope /

    sam:
    block /var/www
}
```
