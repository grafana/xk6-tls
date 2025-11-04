# xk6-tls

A k6 extension for TLS certificates validation and inspection

Check out the extension's documentation [here](https://grafana.com/docs/k6/latest/javascript-api/k6-x-tls).

## Get started

Add the extension's import
```js
import tls from "k6/x/tls";
```

Call the API from the VU context
```js
export default function () {
  const cert = tls.getCertificate("myexample.com:4445");
  // the format of the target is host:[port]
  // if no port is provided then https 443 is used as default port
}
```

## Build

The most common and simple case is to use k6 with [automatic extension resolution](https://grafana.com/docs/k6/latest/extensions/run/#run-a-test-with-extensions). Simply add the extension's import and k6 will resolve the dependency automtically.

However, if you prefer to build it from source using xk6, first ensure you have the prerequisites:

- [Go toolchain](https://go101.org/article/go-toolchain.html)
- Git

Then:

1. Install `xk6`:
  ```shell
  go install go.k6.io/xk6/cmd/xk6@latest
  ```

2. Build the binary:
  ```shell
  xk6 build --with github.com/grafana/xk6-tls
  ```
