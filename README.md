# DNS

DNS server for CSCI 1680 Final project.

------

### Goals:

Our goal was to write a DNS resolver that can act as a local DNS resolver for locally connected computers. We planned on implementing the following features:
* Support simple record types such as A/AAAA
* Pass queries along to a more authoritative DNS server (such as 8.8.8.8)
* Add functionality for caching
* Add functionality for recursively looking up domain names


### Results:

We succeeded in implementing all of our goal functionality. We used the `domain` crate to handle message parsing and creation, and Rust’s socket API to handle communications over the network. We also followed along with this tutorial (https://github.com/EmilHernvall/dnsguide).
