# burp-extensions

**`add_resp_param_to_req-burp_ext.py`**<br>
<p>
  Modified from a couple blogs:
</p>

* https://twelvesec.com/2017/05/05/authorization-token-manipulation/
* https://huntforbug.io/manipulating-authorization-token-using-burp-suite/

<p>
  It's used to pull parameters from JSON response bodies, and then insert/replace them as outgoing headers or body parameters with different names.
</p>
<p>
  It works with a Burp macro, where the last response in the macro contains the parameters needed in the a future request. A Burp session handling rule is then created with a scope of requests that need to be modified. In the session handling rule, which will run whenever one of these requests is about to be sent, configure Burp to run the macro defined above. Burp will offer several options such as "Replace matching parameters in request," but instead select the option for "Invoke an extension," and point to this extension allowing it to preform the matching and replacing.
</p>

