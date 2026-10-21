// Adds the CSRF token (from <meta name="csrf-token">) to every fetch() that
// changes data on this site, so the server can tell the request came from
// one of our own pages. Load it in <head>, before any script that calls fetch.
(function () {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (!meta || !window.fetch) return;

    const token = meta.content;
    const originalFetch = window.fetch;

    window.fetch = function (resource, options = {}) {
        const method = (options.method || (resource instanceof Request ? resource.method : 'GET')).toUpperCase();
        const url = new URL(resource instanceof Request ? resource.url : resource, window.location.href);

        if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && url.origin === window.location.origin) {
            const headers = new Headers(options.headers || {});
            headers.set('X-CSRFToken', token);
            headers.set('X-Requested-With', 'fetch');
            options = Object.assign({}, options, { headers });
        }
        return originalFetch.call(this, resource, options);
    };
})();
