postfix-policy.py
=================

I came up with the idea of creating another policy server for postfix, when i spotted a very
interesting way of levering the current policies. They use compromised accounts to send uce as usual. I'm using [postfix-policyd](http://policyd.org)
already. But you just have two ways of sender based throtteling, either based on the host or based on the sender address
resp. the sasl username. The recommended way of throtteling is the host based type. But what if a spamer has access to a bot net
and sends his crap over thousands or millions of different hosts? I finally switched to user based throtteling to solve that problem. But when
the limits are high to make your server user friendly, they are still able to send the given amount of mail.
The basic idea is now, to check if a certain sender or sasl user is sending mail from different origins in a given
amount of time. If we reach a given number of origins, the policy server denies the request.

Features (done)
---------------
* check for a distributed relay pattern 

Features (to come)
------------------
* throtteling
* whitelisting
* blacklisting

Usage
-----
Currently there is no init script. Start the server by downloading 

`mkdir postfix-policy.py`

`git clone https://github.com/grimmzen/postfix-policy.py.git`

and issuing 

`nohup ./postfix-policy.py >/dev/null 2>&1 &`

on your terminal.
