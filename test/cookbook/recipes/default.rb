#
# Copyright 2017, Noah Kantrowitz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package 'nginx'

directory '/test'

cookbook_file '/test/ca.crt'

cookbook_file '/test/server.key'

cookbook_file '/test/server.crt'

cookbook_file '/test/client.key'

cookbook_file '/test/client.crt'

cookbook_file '/test/client.pem'

file '/test/target' do
  content "Hello world\n"
end

file '/test/nginx.conf' do
  content <<-EOH
daemon off;
master_process off;
worker_processes auto;

events { }

error_log /test/error.log;

http {
  server {
    listen 443;
    ssl on;
    server_name localhost;

    ssl_certificate /test/server.crt;
    ssl_certificate_key  /test/server.key;
    ssl_client_certificate /test/client.crt;
    ssl_verify_client on;

    location / {
      root /test;
    }
  }
}
EOH
end

poise_service 'nginx' do
  command 'nginx -c /test/nginx.conf'
  provider :dummy
end

tls_remote_file '/output' do
  source 'https://localhost/target'
  client_cert '/test/client.crt'
  client_key '/test/client.key'
  ca '/test/ca.crt'
end

tls_remote_file '/output2' do
  source 'https://localhost/target'
  client_cert '/test/client.pem'
  ca '/test/ca.crt'
end
