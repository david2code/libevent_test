# libevent_test
learn libevent2.0
# Reference
> http://www.wangafu.net/~nickm/libevent-book/TOC.html
# Precondition
- Ubuntu20.04
```shell
sudo apt install -y libevent-dev
```
# Sumary
- implement a timer
- use bufferevent
- evbuffer
  - set write buffer get read buffer
  - move buffer without copy
  - do statistics on evbuffer callback function
- set bufferevent speed, group speed [token buckt]
- use evconnlistener
