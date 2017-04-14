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

require 'spec_helper'

describe PoiseTlsRemoteFile::Resources::PoiseTlsRemoteFile do
  step_into(:tls_remote_file)
  let(:tempfile) { Tempfile.new }
  let(:stub_http_response) { double('Net::HTTPResponse', http_version: '1.1', code: '200', msg: 'OK') }
  let(:stub_cert_store) { double('OpenSSL::X509::Store') }
  let(:stub_http) { double('Net::HTTP', proxy_address: nil, cert_store: stub_cert_store) }
  before { override_attributes['test_tempfile'] = tempfile.path }
  after { tempfile.close! }
  before do
    # Stub file loading.
    allow(IO).to receive(:read).and_call_original
    allow(IO).to receive(:read).with('/test/client.crt') { IO.read(File.expand_path('../../../cookbook/files/client.crt', __FILE__)) }
    allow(IO).to receive(:read).with('/test/client.key') { IO.read(File.expand_path('../../../cookbook/files/client.key', __FILE__)) }
    allow(IO).to receive(:read).with('/test/client.pem') { IO.read(File.expand_path('../../../cookbook/files/client.pem', __FILE__)) }
    allow(IO).to receive(:read).with('/test/ca.crt') { IO.read(File.expand_path('../../../cookbook/files/ca.crt', __FILE__)) }
    # Stub core HTTP stuffs.
    allow(Net::HTTP).to receive(:new).with('example.com', 443, nil).and_return(stub_http)
    allow(stub_http).to receive(:proxy_port=).with(nil)
    allow(stub_http).to receive(:use_ssl=).with(true)
    allow(stub_http).to receive(:verify_mode=).with(1)
    allow(stub_http).to receive(:cert_store=)
    allow(stub_http).to receive(:read_timeout=).with(300)
    allow(stub_http).to receive(:open_timeout=).with(300)
    allow(stub_http).to receive(:request).and_yield(stub_http_response)
    allow(stub_cert_store).to receive(:set_default_paths)
    allow(stub_http_response).to receive(:error!)
    allow(stub_http_response).to receive(:each)
    # Attributes.
    override_attributes['poise-tls-remote-file'] = {}
  end
  recipe do
    tls_remote_file node['test_tempfile'] do
      source 'https://example.com/'
    end
  end

  CA_FINGERPRINT = 'fb:f0:76:db:c2:02:c8:53:47:9e:fd:cd:53:e0:99:58'
  CLIENT_FINGERPRINT = '84:9f:57:30:e7:74:d1:fd:d5:a2:d7:72:9c:02:a0:3c'
  SERVER_FINGERPRINT = 'c9:cd:24:86:65:13:33:19:11:0f:0d:06:6f:63:3f:dd'

  def expect_cert(fingerprint)
    expect(stub_http).to receive(:cert=) do |cert|
      expect(cert.public_key.fingerprint).to eq fingerprint
    end
  end

  def expect_key(fingerprint)
    expect(stub_http).to receive(:key=) do |key|
      expect(key.fingerprint).to eq fingerprint
    end
  end

  def expect_add_cert(fingerprint)
    expect(stub_cert_store).to receive(:add_cert) do |cert|
      expect(cert.public_key.fingerprint).to eq fingerprint
    end
  end

  context 'with client_cert' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        client_cert '/test/client.crt'
      end
    end

    it do
      expect_cert(CLIENT_FINGERPRINT)
      run_chef
    end
  end # /context with client_cert

  context 'with client_key' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        client_key '/test/client.key'
      end
    end

    it do
      expect_key(CLIENT_FINGERPRINT)
      run_chef
    end
  end # /context with client_key

  context 'with both client_cert and client_key' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        client_cert '/test/client.crt'
        client_key '/test/client.key'
      end
    end

    it do
      expect_cert(CLIENT_FINGERPRINT)
      expect_key(CLIENT_FINGERPRINT)
      run_chef
    end
  end # /context with both client_cert and client_key

  context 'with ca string' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        ca '/test/ca.crt'
      end
    end

    it do
      expect_add_cert(CA_FINGERPRINT)
      run_chef
    end
  end # /context with ca string

  context 'with ca array' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        ca %w{/test/ca.crt /test/client.crt}
      end
    end

    it do
      expect_add_cert(CA_FINGERPRINT)
      expect_add_cert(CLIENT_FINGERPRINT)
      run_chef
    end
  end # /context with ca array

  context 'with a literal client_cert' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        client_cert <<-EOH
-----BEGIN CERTIFICATE-----
MIIFEjCCAvoCAQIwDQYJKoZIhvcNAQEFBQAwRTELMAkGA1UEBhMCQVUxEzARBgNV
BAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDAeFw0xNzA0MTQwNjIxNTRaFw0xODA0MTQwNjIxNTRaMFkxCzAJBgNVBAYTAkFV
MRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRz
IFB0eSBMdGQxEjAQBgNVBAMTCWxvY2FsaG9zdDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBANsqb+c62APAmf3/TAVBq54e9fJgHshr/I8L0qzj2M5oD7Sr
C+9U01mLSIeJu+CPINpRihR7L0iMT92hBFStlnivdCt+471q/vQTlfOl54DRgvm5
FD10LOkNagSMa9jziSo+25yBKtojrPUN4bt0FjMMDqix/T6P/8xDx+g8hP63CCll
ygwIlvO508IM6+trAqaNbgy7lOhrlKcAjNt86n/hmFV+chdgr5dVYZ5JULtfKNuk
oFLSL56R9pMAGl/v43FsD6w4G2pFndJip5+f46L30gQ7GqkfduPHCjGWwO7rQ6Fz
M2IVDIV+lknExpGGFkcFjPtrXpOVic7aTDk78xhsOu/73In6KNE6QLcRVKFkUIfh
FGWjSXdX5fVLtPiAD0+jbT6qTbwb8ztgHDUbxBZmqeLeabUaNtrbkaAMaJNIW55/
aoiD9CTmtbsl0WFLD+Cji8Ikv1nwAIuV+d2cLSMFOf6kIQHjBA69JqSUqj5ac9IM
oSjlolN+x6RiSVzmplXGc9t4SQ04izTTPQ71ca+IkcaZJpRgm76fdL2YUsHkrzF9
hGvINWtkT++z8hqTnZRxjIRi7TokvwGxmHF7MLoY30Z8L3YMSY8bH2s4ObsS97AP
EMk03HBVncSzzt+yXpAzJDYHgM9K4TzpFieC4ZHcmiKM+fxlwUTA3vFj/rLrAgMB
AAEwDQYJKoZIhvcNAQEFBQADggIBAKahlpkOI4qDpdiwxsfHzIUOoRugpKWRhEKf
ER11JZesoX2mSi2KLNoYncPSmhDc1w5E3szQlCQwWA4iIkEcjCeFB00lIR/rS98F
5JrxN8lCGssBSwM2BGH0ntqDPNTUygxANB8qAIuWA2Kdf1ZJJWlCYY6wmO8LlDRp
nlSw/jXKxigedEhwBvx6/0mgsNT9DbJklfZvcrHNE/YDKBmEObg0vSO4/KDH7HqB
YxWRUmrAJMWq8sARk4eHmo9VTtGT06owWRWeBMFyNUm3U4KMGeexwExPKGPvRgck
XgdgTKdMTOYeKgnXf3hPRn1GV3ikdh6F6DXtzNIGSmjOhj2nDbG57lKhvz5XD5//
JAdnqFyvu3rCJ3xu74x7a7xXac3qdoCqTUsW2CluHb7CDkqhid+hu9+8ZSbsjleq
xbfsRNgqRUiRfLlP/VUw/dOWwArHRw8xN6RIZi3jXsA1TWlG5Y0D2fz14sGANaSN
7j4WbrfQUeF55KM8XKmBVLQtV26sdIWUP8NGjnm8MuxKxWxc9MwAKdWZDzv0KaP/
TKsEDqY1v+5YEeoLzp6AXIPIpj7IuJGArQBI/ASaSr3hpJm7RM2VZIMXwVN6O1S5
iopdV1Wu+B3qDhl9WQpSAra/n/SuMCp821PhSuaRoG/VQyRbNiV63ERSRgmh21Kz
Uuiq6QmL
-----END CERTIFICATE-----
EOH
      end
    end

    it do
      expect_cert(SERVER_FINGERPRINT)
      run_chef
    end
  end # /context with a literal client_cert

  context 'with a literal client_key' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        client_key <<-EOH
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
EOH
      end
    end

    it do
      expect_key(SERVER_FINGERPRINT)
      run_chef
    end
  end # /context with a literal client_key

  context 'with a literal ca' do
    recipe do
      tls_remote_file node['test_tempfile'] do
        source 'https://example.com/'
        ca <<-EOH
-----BEGIN CERTIFICATE-----
MIIFEjCCAvoCAQIwDQYJKoZIhvcNAQEFBQAwRTELMAkGA1UEBhMCQVUxEzARBgNV
BAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDAeFw0xNzA0MTQwNjIxNTRaFw0xODA0MTQwNjIxNTRaMFkxCzAJBgNVBAYTAkFV
MRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRz
IFB0eSBMdGQxEjAQBgNVBAMTCWxvY2FsaG9zdDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBANsqb+c62APAmf3/TAVBq54e9fJgHshr/I8L0qzj2M5oD7Sr
C+9U01mLSIeJu+CPINpRihR7L0iMT92hBFStlnivdCt+471q/vQTlfOl54DRgvm5
FD10LOkNagSMa9jziSo+25yBKtojrPUN4bt0FjMMDqix/T6P/8xDx+g8hP63CCll
ygwIlvO508IM6+trAqaNbgy7lOhrlKcAjNt86n/hmFV+chdgr5dVYZ5JULtfKNuk
oFLSL56R9pMAGl/v43FsD6w4G2pFndJip5+f46L30gQ7GqkfduPHCjGWwO7rQ6Fz
M2IVDIV+lknExpGGFkcFjPtrXpOVic7aTDk78xhsOu/73In6KNE6QLcRVKFkUIfh
FGWjSXdX5fVLtPiAD0+jbT6qTbwb8ztgHDUbxBZmqeLeabUaNtrbkaAMaJNIW55/
aoiD9CTmtbsl0WFLD+Cji8Ikv1nwAIuV+d2cLSMFOf6kIQHjBA69JqSUqj5ac9IM
oSjlolN+x6RiSVzmplXGc9t4SQ04izTTPQ71ca+IkcaZJpRgm76fdL2YUsHkrzF9
hGvINWtkT++z8hqTnZRxjIRi7TokvwGxmHF7MLoY30Z8L3YMSY8bH2s4ObsS97AP
EMk03HBVncSzzt+yXpAzJDYHgM9K4TzpFieC4ZHcmiKM+fxlwUTA3vFj/rLrAgMB
AAEwDQYJKoZIhvcNAQEFBQADggIBAKahlpkOI4qDpdiwxsfHzIUOoRugpKWRhEKf
ER11JZesoX2mSi2KLNoYncPSmhDc1w5E3szQlCQwWA4iIkEcjCeFB00lIR/rS98F
5JrxN8lCGssBSwM2BGH0ntqDPNTUygxANB8qAIuWA2Kdf1ZJJWlCYY6wmO8LlDRp
nlSw/jXKxigedEhwBvx6/0mgsNT9DbJklfZvcrHNE/YDKBmEObg0vSO4/KDH7HqB
YxWRUmrAJMWq8sARk4eHmo9VTtGT06owWRWeBMFyNUm3U4KMGeexwExPKGPvRgck
XgdgTKdMTOYeKgnXf3hPRn1GV3ikdh6F6DXtzNIGSmjOhj2nDbG57lKhvz5XD5//
JAdnqFyvu3rCJ3xu74x7a7xXac3qdoCqTUsW2CluHb7CDkqhid+hu9+8ZSbsjleq
xbfsRNgqRUiRfLlP/VUw/dOWwArHRw8xN6RIZi3jXsA1TWlG5Y0D2fz14sGANaSN
7j4WbrfQUeF55KM8XKmBVLQtV26sdIWUP8NGjnm8MuxKxWxc9MwAKdWZDzv0KaP/
TKsEDqY1v+5YEeoLzp6AXIPIpj7IuJGArQBI/ASaSr3hpJm7RM2VZIMXwVN6O1S5
iopdV1Wu+B3qDhl9WQpSAra/n/SuMCp821PhSuaRoG/VQyRbNiV63ERSRgmh21Kz
Uuiq6QmL
-----END CERTIFICATE-----
EOH
      end
    end

    it do
      expect_add_cert(SERVER_FINGERPRINT)
      run_chef
    end
  end # /context with a literal ca


  context 'with node["poise-tls-remote-file"]["client_cert"]' do
    before { override_attributes['poise-tls-remote-file']['client_cert'] = '/test/client.crt' }
    it do
      expect_cert(CLIENT_FINGERPRINT)
      run_chef
    end
  end # /context with node["poise-tls-remote-file"]["client_cert"]

  context 'with node["poise-tls-remote-file"]["client_key"]' do
    before { override_attributes['poise-tls-remote-file']['client_key'] = '/test/client.key' }
    it do
      expect_key(CLIENT_FINGERPRINT)
      run_chef
    end
  end # /context with node["poise-tls-remote-file"]["client_key"]

  context 'with node["poise-tls-remote-file"]["ca"]' do
    before { override_attributes['poise-tls-remote-file']['ca'] = '/test/ca.crt' }
    it do
      expect_add_cert(CA_FINGERPRINT)
      run_chef
    end
  end # /context with node["poise-tls-remote-file"]["ca"]
end
