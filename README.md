postfix-policy.py
=================

I came up with the idea of creating another policy server for postfix, when i spotted a very
interesting way of levering the current policies. Spammers use compromised accounts to send UCE as usual. I'm using [postfix-policyd](http://policyd.org)
already, but you just have two ways of sender based throtteling, either based on the host or based on the sender address
resp. the sasl username. The recommended way of throtteling is the host based type. But what if a spammer has access to a bot net
and sends his crap over thousands or millions of different hosts? I finally switched to user based throtteling to solve that problem. But when
the limits are high to make your server user friendly, they are still able to send the given amount of mail.
The basic idea is now, to check if a certain sender or sasl user is sending mail from different origins in a timespan.
If we reach a critical number of origins, the policy server denies the request. The advantage is, that this method stops
such attacks in an early stage, before counters go apeshit, and maybe thousands of mails have already been sent.

**At the moment this is just a proof of concept, but the code works though.**

The server uses an in-memory sqlite database which is flushed to disk after shutdown (and loaded on startup) and asyncore
to handle a large amount of requests.

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
Currently there is no init script. Start the server by cloning the repository 

`git clone https://github.com/grimmzen/postfix-policy.py.git`

and issuing 

`nohup postfix-policy.py/postfix-policy.py >/dev/null 2>&1 &`

on your terminal. You can use the policy server by inserting the check_policy_service argument to your smtpd_recipient_restrictions 
to the desired place in the chain in your main.cf, for example:

`smtpd_recipient_restrictions = permit_my_networks, reject_unlisted_sender, check_policy_service inet:127.0.0.1:10032, permit_sasl_authenticated, reject_unauth_destination`

and reloading Postfix. Before starting the server you should change the values in the ''' Setting go here ''' section of the code. I think a
config file would go too far at the moment.

Lean back and watch your /var/log/mail.info.

Cheers

