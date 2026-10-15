# Icmp implementation

## Destination unreachable

To respond with port and protocol unreachable, the upper layer such as the udp / tcp protocols must present to icmp who are the users of the source ports.
If there are no users for these ports, treat them as port unreachable.

If the protocol specified in the ip header is not available, then treat it as protocol unreachable.

Keep this as an API and let the upper layer define the types and pass this to the icmp layer. Icmp layer will then fill this and schedule the message for transport.
