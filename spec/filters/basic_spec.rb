# encoding: utf-8
require 'spec_helper'
require "logstash/timestamp"
require "date"
require "logstash/filters/modsec"

describe LogStash::Filters::Modsec do
  describe "Autitfile basic parser test" do
    let(:config) do <<-CONFIG
      filter {
        modsec { }
      }
    CONFIG
  end
  
  message = "--a2471f66-A--\n[21/May/2017:05:34:21 +0200] WSEKvX8AAQEAAGMO5nAAAABY 187.23.156.83 50424 10.0.0.15 80\n--a2471f66-B--\nPOST /command.php HTTP/1.0\nAccept: */*\nHost: 5.196.53.129\nUser-Agent: Wget(linux)\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 208\n\n--a2471f66-F--\nHTTP/1.1 404 Not Found\nCache-Control: private, no-cache=\"set-cookie\"\nExpires: Sun, 21 May 2017 03:34:21 GMT\nCache-Control: no-cache\nContent-Type: text/html; charset=UTF-8\nSet-Cookie: phpbb3_gvbd6_u=1; expires=Mon, 21-May-2018 03:34:21 GMT; path=/; domain=10.0.0.16; HttpOnly\nSet-Cookie: phpbb3_gvbd6_k=; expires=Mon, 21-May-2018 03:34:21 GMT; path=/; domain=10.0.0.16; HttpOnly\nSet-Cookie: phpbb3_gvbd6_sid=497b4edadc022cf5b674994e034b4a2c; expires=Mon, 21-May-2018 03:34:21 GMT; path=/; domain=10.0.0.16; HttpOnly\nConnection: close\n\n--a2471f66-E--\n\n--a2471f66-H--\nMessage: Warning. Pattern match \"^[\\\\d.:]+$\" at REQUEST_HEADERS:Host. [file \"/etc/modsecurity/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf\"] [line \"793\"] [id \"920350\"] [rev \"2\"] [msg \"Host header is a numeric IP address\"] [data \"5.196.53.129\"] [severity \"WARNING\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"9\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-protocol\"] [tag \"OWASP_CRS/PROTOCOL_VIOLATION/IP_HOST\"] [tag \"WASCTC/WASC-21\"] [tag \"OWASP_TOP_10/A7\"] [tag \"PCI/6.5.10\"]\nMessage: Warning. Pattern match \"(?:;|\\\\{|\\\\||\\\\|\\\\||&|&&|\\\\n|\\\|\\\\$\\\\(|\\\\$\\\\(\\\\(|`|\\\\${|<\\\\(|>\\\\(|\\\\(\\\\s*\\\\))\\\\s*(?:{|\\\\s*\\\\(\\\\s*|\\\\w+=(?:[^\\\\s]*|\\\\$.*|\\\\$.*|<.*|>.*|\\\\'.*\\\\'|\\\".*\\\")\\\\s+|!\\\\s*|\\\\$)*\\\\s*(?:'|\\\")*(?:[\\\\?\\\\*\\\\[\\\\]\\\\(\\\\)\\\\-\\\\|+\\\\w'\\\"\\\\./\\\\\\\\]+/)?[\\\\\\\\'\\\"]*(?:l[\\\\\\\\'\\\"]* ...\" at ARGS:cmd. [file \"/etc/modsecurity/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf\"] [line \"81\"] [id \"932100\"] [rev \"4\"] [msg \"Remote Command Execution: Unix Command Injection\"] [data \"Matched Data: && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt found within ARGS:cmd: cd /var/tmp && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"8\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-shell\"] [tag \"platform-unix\"] [tag \"attack-rce\"] [tag \"OWASP_CRS/WEB_ATTACK/COMMAND_INJECTION\"] [tag \"WASCTC/WASC-31\"] [tag \"OWASP_TOP_10/A1\"] [tag \"PCI/6.5.2\"]\nMessage: Warning. Pattern match \"(?i)(?:;|\\\\{|\\\\||\\\\|\\\\||&|&&|\\\\n|\\\|`)\\\\s*[\\\\(,@\\\\'\\\"\\\\s]*(?:[\\\\w'\\\"\\\\./]+/|[\\\\\\\\'\\\"\\\\^]*\\\\w[\\\\\\\\'\\\"\\\\^]*:.*\\\\\\\\|[\\\\^\\\\.\\\\w '\\\"/\\\\\\\\]*\\\\\\\\)?[\\\"\\\\^]*(?:m[\\\"\\\\^]*(?:y[\\\"\\\\^]*s[\\\"\\\\^]*q[\\\"\\\\^]*l(?:[\\\"\\\\^]*(?:d[\\\"\\\\^]*u[\\\"\\\\^]*m[\\\"\\\\^]*p(?:[\\\"\\\\^]*s[\\\"\\\\^ ...\" at ARGS:cmd. [file \"/etc/modsecurity/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf\"] [line \"185\"] [id \"932110\"] [rev \"4\"] [msg \"Remote Command Execution: Windows Command Injection\"] [data \"Matched Data: && echo found within ARGS:cmd: cd /var/tmp && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-shell\"] [tag \"platform-windows\"] [tag \"attack-rce\"] [tag \"OWASP_CRS/WEB_ATTACK/COMMAND_INJECTION\"] [tag \"WASCTC/WASC-31\"] [tag \"OWASP_TOP_10/A1\"] [tag \"PCI/6.5.2\"]\nMessage: Warning. Pattern match \"(?i:(\\\\!\\\\=|\\\\&\\\\&|\\\\|\\\\||>>|<<|>=|<=|<>|<=>|\\\\bxor\\\\b|\\\\brlike\\\\b|\\\\bregexp\\\\b|\\\\bisnull\\\\b)|(?:not\\\\s+between\\\\s+0\\\\s+and)|(?:is\\\\s+null)|(like\\\\s+null)|(?:(?:^|\\\\W)in[+\\\\s]*\\\\([\\\\s\\\\d\\\"]+[^()]*\\\\))|(?:\\\\bxor\\\\b|<>|rlike(?:\\\\s+binary)?)|(?:regexp\\\\s+ ...\" at ARGS:cmd. [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"526\"] [id \"942120\"] [rev \"3\"] [msg \"SQL Injection Attack: SQL Operator Detected\"] [data \"Matched Data: && found within ARGS:cmd: cd /var/tmp && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"] [tag \"paranoia-level/2\"]\nMessage: Warning. Pattern match \"(?i:([\\\\s'\\\"`\\\\(\\\\)]*?)([\\\\d\\\\w]++)([\\\\s'\\\"`\\\\(\\\\)]*?)(?:(?:=|<=>|r?like|sounds\\\\s+like|regexp)([\\\\s'\\\"`\\\\(\\\\)]*?)\\\\2|(?:!=|<=|>=|<>|<|>|\\\\^|is\\\\s+not|not\\\\s+like|not\\\\s+regexp)([\\\\s'\\\"`\\\\(\\\\)]*?)(?!\\\\2)([\\\\d\\\\w]+)))\" at ARGS:cmd. [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"558\"] [id \"942130\"] [rev \"2\"] [msg \"SQL Injection Attack: SQL Tautology Detected.\"] [data \"Matched Data: x3610cker > 610cker found within ARGS:cmd: cd /var/tmp && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"] [tag \"paranoia-level/2\"]\nMessage: Warning. Pattern match \"((?:[\\\\~\\\\!\\\\@\\\\#\\\\$\\\\%\\\\^\\\\&\\\\*\\\\(\\\\)\\\\-\\\\+\\\\=\\\\{\\\\}\\\\[\\\\]\\\\|\\\\:\\\\;\\\"\\\\'\\\\\\xc2\\xb4\\\\\\xe2\\x80\\x99\\\\\\xe2\\x80\\x98\\\\`\\\\<\\\\>][^\\\\~\\\\!\\\\@\\\\#\\\\$\\\\%\\\\^\\\\&\\\\*\\\\(\\\\)\\\\-\\\\+\\\\=\\\\{\\\\}\\\\[\\\\]\\\\|\\\\:\\\\;\\\"\\\\'\\\\\\xc2\\xb4\\\\\\xe2\\x80\\x99\\\\\\xe2\\x80\\x98\\\\`\\\\<\\\\>]*?){6})\" at ARGS:cmd. [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"1216\"] [id \"942431\"] [rev \"2\"] [msg \"Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)\"] [data \"Matched Data: && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && found within ARGS:cmd: cd /var/tmp && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt\"] [severity \"WARNING\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"] [tag \"paranoia-level/3\"]\nMessage: Warning. Pattern match \"\\\\W{4}\" at ARGS:cmd. [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"1251\"] [id \"942460\"] [rev \"2\"] [msg \"Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters\"] [data \"Matched Data:  &&  found within ARGS:cmd: cd /var/tmp && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt\"] [severity \"WARNING\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"8\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"] [tag \"paranoia-level/3\"]\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Error: [file \"apache2_util.c\"] [line 273] [level 3] [client %s] ModSecurity: %s%s [uri \"%s\"]%s\nApache-Handler: proxy-server\nStopwatch: 1495337661214004 25113 (- - -)\nStopwatch2: 1495337661214004 25113; combined=2097, p1=306, p2=1563, p3=87, p4=130, p5=11, sr=48, sw=0, l=0, gc=0\nResponse-Body-Transformed: Dechunked\nProducer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.0.0.\nServer: Apache/2.4.18 (Ubuntu)\nEngine-Mode: \"DETECTION_ONLY\"\n\n--a2471f66-Z--"


    sample("message" => message) do

      # Test section A
      expect(subject.get("@timestamp").to_s).to eq("2017-05-21T03:34:21.000Z")
      expect(subject.get("transactionId")).to eq("WSEKvX8AAQEAAGMO5nAAAABY")
      expect(subject.get("ip_src")).to eq("187.23.156.83")
      expect(subject.get("port_src")).to eq("50424")
      expect(subject.get("ip_dest")).to eq("10.0.0.15")
      expect(subject.get("port_dest")).to eq("80")

      # Test secion B
      expect(subject.get("http_method")).to eq("POST")
      expect(subject.get("http_url")).to eq("/command.php")
      expect(subject.get("http_query")).to eq(nil)
      expect(subject.get("request_http_version")).to eq("HTTP/1.0")

      expect(subject.get("request_user-agent")).to eq("Wget(linux)")
      expect(subject.get("request_content-type")).to eq("application/x-www-form-urlencoded")
      expect(subject.get("request_content-length")).to eq("208")

      # Test section F
      expect(subject.get("http_version")).to eq("HTTP/1.1")
      expect(subject.get("status_code")).to eq("404")
      expect(subject.get("status_message")).to eq("Not Found")

      # Test alert 1
      expect(subject.get("alert_0")["action"]).to eq("Warning. Pattern match \"(?:;|\\\\{|\\\\||\\\\|\\\\||&|&&|\\\\n|\\\|\\\\$\\\\(|\\\\$\\\\(\\\\(|`|\\\\${|<\\\\(|>\\\\(|\\\\(\\\\s*\\\\))\\\\s*(?:{|\\\\s*\\\\(\\\\s*|\\\\w+=(?:[^\\\\s]*|\\\\$.*|\\\\$.*|<.*|>.*|\\\\'.*\\\\'|\\\".*\\\")\\\\s+|!\\\\s*|\\\\$)*\\\\s*(?:'|\\\")*(?:[\\\\?\\\\*\\\\[\\\\]\\\\(\\\\)\\\\-\\\\|+\\\\w'\\\"\\\\./\\\\\\\\]+/)?[\\\\\\\\'\\\"]*(?:l[\\\\\\\\'\\\"]* ...\" at ARGS:cmd. ")
      expect(subject.get("alert_0")["rule_line"]).to eq("81")
      expect(subject.get("alert_0")["rule_file"]).to eq("/etc/modsecurity/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf")
      expect(subject.get("alert_0")["rule_rev"]).to eq("4")
      expect(subject.get("alert_0")["rule_id"]).to eq("932100")
      expect(subject.get("alert_0")["message"]).to eq("Remote Command Execution: Unix Command Injection")
      expect(subject.get("alert_0")["data"]).to eq("Matched Data: && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt found within ARGS:cmd: cd /var/tmp && echo -ne \\x5c\\x5cx3610cker > 610cker.txt && cat 610cker.txt")
      expect(subject.get("alert_0")["severity"]).to eq("CRITICAL")
      expect(subject.get("alert_0")["version"]).to eq("OWASP_CRS/3.0.0")
      expect(subject.get("alert_0")["maturity"]).to eq("8")
      expect(subject.get("alert_0")["accuracy"]).to eq("8")
      expect(subject.get("alert_0")["tags"]).to eq(["application-multi","language-shell","platform-unix","attack-rce","OWASP_CRS/WEB_ATTACK/COMMAND_INJECTION","WASCTC/WASC-31","OWASP_TOP_10/A1","PCI/6.5.2"])

      # Test alert 5
      expect(subject.get("alert_4")["action"]).to eq("Warning. Pattern match \"^[\\\\d.:]+$\" at REQUEST_HEADERS:Host. ")
      expect(subject.get("alert_4")["rule_line"]).to eq("793")
      expect(subject.get("alert_4")["rule_file"]).to eq("/etc/modsecurity/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
      expect(subject.get("alert_4")["rule_rev"]).to eq("2")
      expect(subject.get("alert_4")["rule_id"]).to eq("920350")
      expect(subject.get("alert_4")["message"]).to eq("Host header is a numeric IP address")
      expect(subject.get("alert_4")["data"]).to eq("5.196.53.129")
      expect(subject.get("alert_4")["severity"]).to eq("WARNING")
      expect(subject.get("alert_4")["version"]).to eq("OWASP_CRS/3.0.0")
      expect(subject.get("alert_4")["maturity"]).to eq("9")
      expect(subject.get("alert_4")["accuracy"]).to eq("9")

      # Test metrics
      expect(subject.get("alerts_emergency")).to eq(0)
      expect(subject.get("alerts_alert")).to eq(0)
      expect(subject.get("alerts_critical")).to eq(4)
      expect(subject.get("alerts_warning")).to eq(3)
      expect(subject.get("alerts_error")).to eq(0)

      expect(subject.get("alert_count")).to eq(7)
    end
  end
end
