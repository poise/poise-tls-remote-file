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

require 'chef/resource/remote_file'
require 'chef/provider/remote_file'


module PoiseTlsRemoteFile
  module Resources
    # (see PoiseTlsRemoteFile::Resource)
    # @since 1.0.0
    module PoiseTlsRemoteFile
      # A `tls_remote_file` resource to do something.
      #
      # @provides tls_remote_file
      # @action run
      # @example
      #   tls_remote_file '/path/to/file' do
      #     client_cert '/etc/ssl/client.crt'
      #     client_key '/etc/ssl/private/client.key'
      #   end
      class Resource < Chef::Resource::RemoteFile
        resource_name(:tls_remote_file)

        def initialize(*args)
          super
          @provider = PoiseTlsRemoteFile::Provider if defined?(@provider)
        end

        property(:client_cert, kind_of: [String, NilClass], default: lazy { default_client_cert })
        property(:client_key, kind_of: [String, NilClass], default: lazy { default_client_key })
        property(:ca, kind_of: [String, Array, NilClass], default: lazy { default_ca })

        def client_cert_obj
          OpenSSL::X509::Certificate.new(maybe_read_file(client_cert)) if client_cert
        end

        def client_key_obj
          if client_key
            OpenSSL::PKey::RSA.new(maybe_read_file(client_key))
          elsif client_cert
            begin
              OpenSSL::PKey::RSA.new(maybe_read_file(client_cert))
            rescue OpenSSL::PKey::RSAError
              # It didn't have a key in it, oh well.
              nil
            end
          end
        end

        def ca_objs
          Array(ca).map do |path|
            OpenSSL::X509::Certificate.new(maybe_read_file(path)) if path
          end
        end

        private

        def default_client_cert
          node['poise-tls-remote-file']['client_cert']
        end

        def default_client_key
          node['poise-tls-remote-file']['client_key']
        end

        def default_ca
          node['poise-tls-remote-file']['ca']
        end

        def maybe_read_file(path)
          if path =~ /\A(\/|\w:)/
            IO.read(path)
          else
            # Looks like a literal value.
            path
          end
        end
      end

      # Provider for `tls_remote_file`.
      #
      # @see Resource
      # @provides tls_remote_file
      class Provider < Chef::Provider::RemoteFile
        provides(:tls_remote_file)

        def initialize(*args)
          super
          @content_class = PoiseTlsRemoteFile::Content
        end
      end

      # Content class for `tls_remote_file`.
      #
      # @see Resource
      class Content < Chef::Provider::RemoteFile::Content
        def grab_file_from_uri(uri)
          PoiseTlsRemoteFile::Fetcher.new(uri, @new_resource, @current_resource).fetch
        end
      end

      # Fetcher class for `tls_remote_file`.
      #
      # @see Resource
      class Fetcher < Chef::Provider::RemoteFile::HTTP
        def fetch
          http = Chef::HTTP::Simple.new(uri, http_client_opts)
          # START OF CHANGES
          client_cert = new_resource.client_cert_obj
          client_key = new_resource.client_key_obj
          ca = new_resource.ca_objs
          http.singleton_class.prepend(Module.new {
            define_method(:http_client) do |*args|
              super(*args).tap do |client|
                client.http_client.cert = client_cert if client_cert
                client.http_client.key = client_key if client_key
                ca.each {|cert| client.http_client.cert_store.add_cert(cert) if cert }
              end
            end
          })
          # END OF CHANGES
          if want_progress?
            tempfile = http.streaming_request_with_progress(uri, headers) do |size, total|
              events.resource_update_progress(new_resource, size, total, progress_interval)
            end
          else
            tempfile = http.streaming_request(uri, headers)
          end
          if tempfile
            update_cache_control_data(tempfile, http.last_response)
            tempfile.close
          end
          tempfile
        end
      end

    end
  end
end

