So you've chosen volence!

fail2ban supports many more uses, but requires too much attention to configure
correctly; benevolence is opinionated, so you don't have to be.

Opinions
* nft > iptables
* logs should be low noise; banning noisy hosts helps
* lying is proof of malign intent
* binary logs are dumb
* firewall configuration isn't benevolence's job


### Example config

```ini
[files]
# normal file, benevolence will run all rules against it
file = /var/log/messages

# wildcard for specific ruleset
nginx = /var/log/nginx/*.log

# default bantime, specific rules may specify a different amount of time
bantime = 14d
```
