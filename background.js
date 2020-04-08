browser.webRequest.onBeforeSendHeaders.addListener(
    async function (details) {

        // ignore asset files
        if (new URL(location.href).pathname.search(/\.(js|svg|axd|map|woff|woff2|ttf|otf|gif|jpg|png|css)$/i) > 0 ) {
            return {requestHeaders: details.requestHeaders};
        }

        c_name = "Default";
        if (details.tabId !== browser.tabs.TAB_ID_NONE) {
            tab = await browser.tabs.get(details.tabId);
            containers = await browser.contextualIdentities.query({});
            containers.forEach((container) => {
                if (container.cookieStoreId == tab.cookieStoreId) {
                    c_name = container.name;
                }
            });
        }
        headers = details.requestHeaders;
        // { name: "Host", value: "www.google.com" }
        headers.push({ name:"X-CONTAINER-ID", value: c_name});
        // console.log(c_name);
        // console.log(headers);
        return {requestHeaders: headers};
    }, 
    {
        urls: ["<all_urls>"]
    },
    ["blocking", "requestHeaders"]
);