Adds a customer header (`X-CONTAINER-ID`) to requests (except common asset extensions) with the name of the current container or `default`.

See https://addons.mozilla.org/en-GB/firefox/addon/multi-account-containers/

Install the `.xpi` in Firefox (Menu -> Add-ons -> Cog icon -> Install from file). You will probably need to enable installation of untrusted extensions (`about:config` `xpinstall.signatures.required` = False)

There's also a Burp `jython` extension which can auto-highlight rows in Proxy History. If the container name is an valid colour (see below), it will be applied. Alternatively there's a mapping JSON file. Right-click in Burp's Proxy history, choose `Highlight Firefox Container`, and see the options. `Edit Mappings` will launch an editor. A sample should be included by default:

```javascript
{
    "sample_container_name_1": "red",
    "sample_container_name_2": "green"
}
```

The valid colours are:
- red
- blue
- pink
- green
- magenta
- cyan
- orange
- gray
- yellow

If there is no mapping or match, it won't highight. But it will add a comment with the container name either way.

There's also an option "Remove Header" which will create an Edited Request with the header removed.
