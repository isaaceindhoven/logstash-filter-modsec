# encoding: utf-8
require 'spec_helper'
require "logstash/timestamp"
require "date"
require "logstash/filters/modsec"

describe LogStash::Filters::Modsec do
  describe "Combine alerts in array test" do
    let(:config) do <<-CONFIG
      filter {
        modsec { 
          split_alerts => false
          store_response => true
        }
      }
    CONFIG
  end
  
  message = "--b542813c-A--\n[20/Jun/2017:10:52:00 +0000] WUj@R6wVAAYAAAAWDDAAAAAE 172.22.0.1 44478 172.22.0.6 8080\n--b542813c-B--\nGET /categoriesServlet?q=%27/**/AND%20(select%20substring((select%20userid%20from%20user_%20LIMIT%200,1),1,1)%20LIKE%20BINARY%20%27a%27)%20and%20sleep(1)/**/or%20tree.child%20like%20%27xxx HTTP/1.1\nHost: localhost:8080\nConnection: keep-alive\nCache-Control: max-age=0\nUpgrade-Insecure-Requests: 1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\nDNT: 1\nAccept-Encoding: gzip, deflate, sdch, br\nAccept-Language: en-GB,en;q=0.8,en-US;q=0.6,nl;q=0.4\nCookie: dmid=3236647a-cdcc-4947-994d-9d55afd6cb58\n\n--b542813c-F--\nHTTP/1.1 200 OK\nCache-Control: public, no-store, no-cache, max-age=0\nPragma: no-cache\nExpires: Tue, 20 Jun 2017 10:51:51 GMT\nContent-Type: text/plain;charset=utf-8\nContent-Length: 24\nKeep-Alive: timeout=5, max=100\nConnection: Keep-Alive\n\n--b542813c-E--\n{\"numRows\":0,\"items\":[]}\n--b542813c-H--\nMessage: Warning. detected SQLi using libinjection with fingerprint 's&(Ef' [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"68\"] [id \"942100\"] [rev \"1\"] [msg \"SQL Injection Attack Detected via libinjection\"] [data \"Matched Data: s&(Ef found within ARGS:q: '/**/AND (select substring((select userid from user_ LIMIT 0,1),1,1) LIKE BINARY 'a') and sleep(1)/**/or tree.child like 'xxx\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"1\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"]\nMessage: Warning. detected SQLi using libinjection with fingerprint 's&(Ef' [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"68\"] [id \"942100\"] [rev \"1\"] [msg \"SQL Injection Attack Detected via libinjection\"] [data \"Matched Data: s&(Ef found within ARGS:q: 'AND (select substring((select userid from user_ LIMIT 0,1),1,1) LIKE BINARY 'a') and sleep(1)or tree.child like 'xxx\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"1\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"]\nMessage: Warning. Pattern match \"(?i:(sleep\\\\((\\\\s*?)(\\\\d*?)(\\\\s*?)\\\\)|benchmark\\\\((.*?)\\\\,(.*?)\\\\)))\" at ARGS:q. [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"127\"] [id \"942160\"] [rev \"2\"] [msg \"Detects blind sqli tests using sleep() or benchmark().\"] [data \"Matched Data: sleep(1) found within ARGS:q: '/**/AND (select substring((select userid from user_ LIMIT 0,1),1,1) LIKE BINARY 'a') and sleep(1)/**/or tree.child like 'xxx\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"]\nMessage: Warning. detected SQLi using libinjection with fingerprint 's&(Ef' [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"68\"] [id \"942100\"] [rev \"1\"] [msg \"SQL Injection Attack Detected via libinjection\"] [data \"Matched Data: s&(Ef found within ARGS:q: '/**/AND (select substring((select userid from user_ LIMIT 0,1),1,1) LIKE BINARY 'a') and sleep(1)/**/or tree.child like 'xxx\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"1\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"]\nMessage: Warning. detected SQLi using libinjection with fingerprint 's&(Ef' [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"68\"] [id \"942100\"] [rev \"1\"] [msg \"SQL Injection Attack Detected via libinjection\"] [data \"Matched Data: s&(Ef found within ARGS:q: 'AND (select substring((select userid from user_ LIMIT 0,1),1,1) LIKE BINARY 'a') and sleep(1)or tree.child like 'xxx\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"1\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"]\nMessage: Warning. Pattern match \"(?i:(sleep\\\\((\\\\s*?)(\\\\d*?)(\\\\s*?)\\\\)|benchmark\\\\((.*?)\\\\,(.*?)\\\\)))\" at ARGS:q. [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"127\"] [id \"942160\"] [rev \"2\"] [msg \"Detects blind sqli tests using sleep() or benchmark().\"] [data \"Matched Data: sleep(1) found within ARGS:q: '/**/AND (select substring((select userid from user_ LIMIT 0,1),1,1) LIKE BINARY 'a') and sleep(1)/**/or tree.child like 'xxx\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"]\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Handler: proxy-server\nStopwatch: 1497955911288001 9283603 (- - -)\nStopwatch2: 1497955911288001 9283603; combined=3591, p1=472, p2=2769, p3=75, p4=218, p5=56, sr=15, sw=1, l=0, gc=0\nResponse-Body-Transformed: Dechunked\nProducer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.0.2; OWASP_CRS/3.0.2.\nServer: Apache\nEngine-Mode: \"DETECTION_ONLY\"\n\n--b542813c-Z--"

    sample("message" => message) do

      # Test response body 
      expect(subject.get("_response_body")).to eq("{\"numRows\":0,\"items\":[]}")

      # Test section A
      expect(subject.get("@timestamp").to_s).to eq("2017-06-20T10:52:00.000Z")
      expect(subject.get("transactionId")).to eq("WUj@R6wVAAYAAAAWDDAAAAAE")
      expect(subject.get("ip_src")).to eq("172.22.0.1")
      expect(subject.get("port_src")).to eq("44478")
      expect(subject.get("ip_dest")).to eq("172.22.0.6")
      expect(subject.get("port_dest")).to eq("8080")
      

      # Test secion B
      expect(subject.get("http_method")).to eq("GET")
      expect(subject.get("http_url")).to eq("/categoriesServlet")
      expect(subject.get("http_query")).to eq("?q=%27/**/AND%20(select%20substring((select%20userid%20from%20user_%20LIMIT%200,1),1,1)%20LIKE%20BINARY%20%27a%27)%20and%20sleep(1)/**/or%20tree.child%20like%20%27xxx")
      expect(subject.get("request_http_version")).to eq("HTTP/1.1")
      expect(subject.get("request_user-agent")).to eq("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")

      # Test section F
      expect(subject.get("http_version")).to eq("HTTP/1.1")
      expect(subject.get("status_code")).to eq("200")
      expect(subject.get("status_message")).to eq("OK")

      # Test alert
      expect(subject.get("alerts")[5]["action"]).to eq("Warning. Pattern match \"(?i:(sleep\\\\((\\\\s*?)(\\\\d*?)(\\\\s*?)\\\\)|benchmark\\\\((.*?)\\\\,(.*?)\\\\)))\" at ARGS:q. ")
      expect(subject.get("alerts")[5]["rule_line"]).to eq("127")
      expect(subject.get("alerts")[5]["rule_file"]).to eq("/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
      expect(subject.get("alerts")[5]["rule_id"]).to eq("942160")
      expect(subject.get("alerts")[5]["rule_rev"]).to eq("2")
      expect(subject.get("alerts")[5]["message"]).to eq("Detects blind sqli tests using sleep() or benchmark().")
      expect(subject.get("alerts")[5]["data"]).to eq("Matched Data: sleep(1) found within ARGS:q: '/**/AND (select substring((select userid from user_ LIMIT 0,1),1,1) LIKE BINARY 'a') and sleep(1)/**/or tree.child like 'xxx")
      expect(subject.get("alerts")[5]["severity"]).to eq("CRITICAL")
      expect(subject.get("alerts")[5]["version"]).to eq("OWASP_CRS/3.0.0")
      expect(subject.get("alerts")[5]["maturity"]).to eq("9")
      expect(subject.get("alerts")[5]["accuracy"]).to eq("8")
      expect(subject.get("alerts")[5]["tags"]).to eq(["application-multi", "language-multi", "platform-multi", "attack-sqli", "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"])

      # Test metrics
      expect(subject.get("alerts_emergency")).to eq(0)
      expect(subject.get("alerts_alert")).to eq(0)
      expect(subject.get("alerts_critical")).to eq(6)
      expect(subject.get("alerts_warning")).to eq(0)
      expect(subject.get("alerts_error")).to eq(0)

      expect(subject.get("alert_count")).to eq(6)
    end
  end
end
