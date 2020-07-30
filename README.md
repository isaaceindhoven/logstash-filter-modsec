# Logstash Filter for Modsecurity logging

This is a filter plugin for [Logstash](https://github.com/elastic/logstash) to parse [ModSecurity](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats) audit log files.
Tested in conjunction with [OWASP Core Rule Set](https://github.com/SpiderLabs/owasp-modsecurity-crs).
This plugin will parse the fairly incomprehensible ModSecurity 'auditlog' format using a Logstash Filter to facilitate Modsecurity event storage, analysis and correlation using Elastic.
## Use case
This plugin for Logstash can be used to parse Modsecurity audit log files and push them to an Elasticsearch cluster. Once the data has been indexed the user can visualize, analyze and investigate ModSecurity events with tools like [Kibana](https://github.com/elastic/kibana). Centralizing and indexing  ModSecurity alerts also facilitates the capability to easily identify false-positives and adjust the ModSecurity configuration to increase detection accuracy. Real-time monitoring and alerting can be achived with tools such as [Grafana](https://github.com/grafana/grafana) and  [ElastAlert](https://github.com/Yelp/elastalert), providing the user real-time treat awareness. 

## Settings:

**split_alerts**  
Split all alerts into separate fields (eg. alert_1, alert_2). If set to false all alerts will be combined in a single field named 'alerts' which will contain an array of alert objects. Object arrays are not (yet) properly supported by Kibana. Keep in mind that having a lot of messages per alert will result in exceeding the 'index.mapping.total_fiels.limit'. To prevent exceeding this limit, all alerts with more than 6 messages will have the remaining messages combined in a separate msgOther field.
As of June 2017, there is an unofficial plugin that supports object arrays in Kibana available on [Github](https://github.com/istresearch/kibana-object-format). 

**store_request (ModSecurity Section I) & store_response (ModSecurity Section E)**  
Setting this value to ```true``` will push the entire request, if present in the auditlog, to the output. It is advisable to disable indexing on ```_request_body```

**request_headers (ModSecurity Section B) & request_headers (ModSecurity Section F)**  
Case insensitive list of header keys that that should be extracted if present. Will be stored as a separate field in the output with 'request_' as prefix (eg. request_cookie).

## Usage
**logstash.yml example**

```
filter {
   modsec {
       split_alerts => boolean (default true)
       store_request => boolean (default false)
       store_response => boolean (default false)
       request_headers => csv header keys (default "host,content-length,user-agent,cookie,content-type,origin,refferer")
       response_headers => csv header keys (default "content-length")
   }
}
```

## Developing, building, testing and installing


#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec spec
```


#### Run in an installed Logstash

- Build your plugin gem
```sh
gem build logstash-filter-modsec.gemspec
```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install logstash-filter-modsec-0.1.0.gem
```
- Start Logstash and proceed to test the plugin

# License
MIT License

Copyright (c) 2020 ISAAC E-commerce Solutions BV

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
