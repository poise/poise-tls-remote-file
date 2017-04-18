# Poise-TLS-Remote-File Cookbook

[![Build Status](https://img.shields.io/travis/poise/poise-tls-remote-file.svg)](https://travis-ci.org/poise/poise-tls-remote-file)
[![Gem Version](https://img.shields.io/gem/v/poise-tls-remote-file.svg)](https://rubygems.org/gems/poise-tls-remote-file)
[![Cookbook Version](https://img.shields.io/cookbook/v/poise-tls-remote-file.svg)](https://supermarket.chef.io/cookbooks/poise-tls-remote-file)
[![Coverage](https://img.shields.io/codecov/c/github/poise/poise-tls-remote-file.svg)](https://codecov.io/github/poise/poise-tls-remote-file)
[![Gemnasium](https://img.shields.io/gemnasium/poise/poise-tls-remote-file.svg)](https://gemnasium.com/poise/poise-tls-remote-file)
[![License](https://img.shields.io/badge/license-Apache_2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

A [Chef](https://www.chef.io/) cookbook to download files over HTTPS using TLS
client certificate authentication or with custom CA certificates.

## Quick Start

To download a file using TLS client certificate authentication:

```ruby
tls_remote_file '/path/to/file' do
  client_cert '/etc/ssl/client.crt'
  client_key '/etc/ssl/private/client.key'
end
```

To specify a CA certificate for the download:

```ruby
tls_remote_file '/path/to/file' do
  ca '/etc/ssl/mycompany.crt'
end
```

Certificates and keys can also be specified in-line as strings or retrieved
from other APIs like Chef data bags:

```ruby
tls_remote_file '/path/to/file' do
  client_cert data_bag_item('client_keys', node.chef_environment)['key']
  ca <<-EOH
-----BEGIN CERTIFICATE-----
MIIFEjCCAvoCAQIwDQYJKoZIhvcNAQEFBQAwRTELMAkGA1UEBhMCQVUxEzARBgNV
...
-----END CERTIFICATE-----
EOH
end
```

## Attributes

* `node['poise-tls-remote-file']['client_cert']` – Default client_cert for all
  `tls_remote_file` resources.
* `node['poise-tls-remote-file']['client_key']` – Default client_key for all
  `tls_remote_file` resources.
* `node['poise-tls-remote-file']['ca']` – Default ca for all `tls_remote_file`
  resources.

## Resources

### `tls_remote_file`

The `tls_remote_file` resource downloads a file using TLS client certificate
authentication.

```ruby
tls_remote_file '/path/to/file' do
  client_cert '/etc/ssl/client.crt'
  client_key '/etc/ssl/private/client.key'
  ca '/etc/ssl/ca.crt'
end
```

#### Actions

All actions are the same as the core `remote_file` resource.

#### Properties

* `client_cert` – Path or PEM encoded TLS certificate to use for the client. Can
  also be set to a combined certificate and key file.
* `client_key` – Path or PEM encoded TLS key to use for the client.
* `ca` – Path or PEM encoded TLS certificate to add to the standard Chef trusted
  CA certificates. Can be passed as an array to add multiple certificates.

All other properties are the same as the core `remote_file` resource.

## Sponsors

Development sponsored by [SAP](https://www.sap.com/).

The Poise test server infrastructure is sponsored by [Rackspace](https://rackspace.com/).

## License

Copyright 2017, Noah Kantrowitz

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
