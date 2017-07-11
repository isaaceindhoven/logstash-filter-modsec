# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/timestamp"
require "date"

class LogStash::Filters::Modsec < LogStash::Filters::Base
	config_name "modsec"
	config :split_alerts, :validate => :boolean, :default => true
	config :store_request, :validate => :boolean, :default => false
	config :store_response, :validate => :boolean, :default => false
	config :request_headers, :validate => :string, :default => "host,content-length,user-agent,cookie,content-type,origin,refferer"
	config :response_headers, :validate => :string, :default => "content-length"
	public
	def register

	end
	public
	def filter(event)
		lines = event.get("message").split("\n")

		if (lines == nil || lines.length < 4)
		   event.set("parse_errors", event.get("message"))
		   @logger.error("Unvalid event provided to Modsecurity filter")
           filter_matched(event)
		   return
		end

		requestHeaders = @request_headers.split(',')
		responseHeaders = @response_headers.split(',')
		firstReqLine = true
		firstRespLine = true

		parseErrors = []
		section = ""
		respBody = ""
		reqBody = ""

		# Separate array declaration is faster (and uglier) than sorting afterwards
		alertsEmergency = []
		alertsAlert = []
		alertsCritical = []
		alertsError = []
		alertsWarning = []
		alertsOther = []

		alertCountEmergency = 0
		alertCountAlert = 0
		alertCountCritital = 0
		alertCountError = 0
		alertCountWarning = 0

		event.set('message',nil)
		for line in lines do
			if (line.length == 0)
				next
			end

			# Marks the start, or end, of a section (https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats#Audit_Log)
			if (line.start_with?("--") && line.end_with?("--"))
				index = line.rindex('--')  - 1
				section = line[index, 1]
				firstLine = true
				next
			end

			# Audit log header
			if section == "A" 
				match = line.match("\\[(?<timestamp>[^\\]]+)\] (?<transaction>[^\\s]+) (?<ip_src>[^\\s]+) (?<port_src>[^\\s]+) (?<ip_dest>[^\\s]+) (?<port_dest>[^\\s]+).*");
				timestamp = match[:timestamp];
				format = "%d/%b/%Y:%H:%M:%S %z"
                parsed = DateTime.strptime(timestamp, format)
				parsedLogstash = LogStash::Timestamp.at(parsed.strftime('%s').to_i)
				event.set("@timestamp",parsedLogstash)
				event.set("transactionId", match[:transaction])
				event.set("ip_src", match[:ip_src])
				event.set("port_src", match[:port_src])
				event.set("ip_dest", match[:ip_dest])
				event.set("port_dest", match[:port_dest])

			# Request headers
			elsif section == "B" 
				if firstReqLine
					match = line.match("(?<method>[^\\s]+) (?<url>([^\\?\\s])+)(?<query>[^\\s]+)? (?<version>[^\\s]+).*");
					firstReqLine = false
					event.set("http_method", match[:method])
					event.set("http_url", match[:url])
					event.set("http_query", match[:query])
					event.set("request_http_version", match[:version])
					next
				end
				splitPoint = line.index(": ");
				if (splitPoint == nil)
					parseErrors << "REQUEST HEADER: " + line
					next
				end
				
				key = line[0,splitPoint].downcase
				value = line[(splitPoint + 2)..line.length]
				if (requestHeaders.include? key)
					if key == "cookie"
					  event.set("request_" + key, value.split("; "))
				    else
					  event.set("request_" + key, value)
					end
				end
			
			# Audit log trailer
			elsif section == "H" 
				splitPoint = line.index(": ");
				key = line[0,splitPoint].downcase
				value = line[(splitPoint + 2)..line.length]
				if key == "action"
					event.set("action_2",value) 
				end
				if key == "message"
					match = value.match("(?<action>(?!file).+)\\[file \"(?<rulefile>[^\"]+)\"\\] \\[line \"(?<ruleline>\\d+)\"\\] \\[id \"(?<ruleid>\\d+)\"\\] (\\[rev \"(?<rev>\\d+)\"\\] )?\\[msg \"(?<msg>[^\"]+)\"\\] (\\[data \"(?<data>[^\"]+)\"\\] )?(\\[severity \"(?<severity>[^\"]+)\"\\] )?(\\[ver \"(?<ver>[^\"]+)\"\\] )?(\\[maturity \"(?<maturity>\\d+)\"\\] )?(\\[accuracy \"(?<accuracy>\\d+)\"\\] )?.*") 
					if match == nil
					  @logger.warn("Modsecurity filter: unable to match alert message.")
                      parseErrors << "MESSAGE: " + value
					  next
					end
					begin
						alert = {}
						alert[:action] = match[:action]
						alert[:rule_line] = match[:ruleline]
						alert[:rule_id] = match[:ruleid]
						alert[:rule_file] = match[:rulefile]
						alert[:rule_rev] = match[:rev]
						alert[:message] = match[:msg]
						alert[:data] = match[:data]
						alert[:severity] = match[:severity]
						alert[:version] = match[:ver]
						alert[:maturity] = match[:maturity]
						alert[:accuracy] = match[:accuracy]
	
						#Parse tags
						alert_tags = []
						tagStart = 0;
						begin # Catch max tag limit reached 
							while (tagStart = value.index('[tag "', tagStart)) != nil
								tagEnd = value.index('"]', tagStart)
								alert_tags << value[(tagStart + 6)...tagEnd]
								tagStart = tagEnd;
							end
						rescue => exception
						  parseErrors << "TAG_PARSE_FAILURE: " + value
						end
						alert[:tags] = alert_tags

						if alert[:severity] != nil
							severityLower = alert[:severity].downcase
							if severityLower == "emergency"
								alertCountEmergency += 1
								alertsEmergency << alert
							elsif severityLower == "alert"
								alertCountAlert += 1
								alertsAlert << alert
							elsif severityLower == "critical"
								alertCountCritital += 1
								alertsCritical << alert					
							elsif severityLower == "error"
								alertCountError += 1
								alertsError << alert
							elsif severityLower == "warning"
								alertCountWarning += 1
								alertsWarning << alert
							else
								alertsOther << alert
							end
						else
							alertsOther << alert
						end	
					rescue => exception
						  @logger.warn("Modsecurity filter: unable to match alert message.")
						  parseErrors << "MESSAGE_EXCEPTION: " + value + "\n\n"
					end
				end

			# Response headers
			elsif section == "F" 
				if firstRespLine 
					match = line.match("(?<version>[^\\s]+) (?<statuscode>\\d{3}) (?<message>.*).*");
					firstRespLine = false
					event.set("http_version", match[:version])
					event.set("status_code", match[:statuscode])
					event.set("status_message", match[:message])
					next
				end
				splitPoint = line.index(": ");
				if (splitPoint == nil)
					parseErrors << "RESPONSE HEADER: " + line
					next
				end
				key = line[0,splitPoint].downcase
				value = line[(splitPoint + 2)..line.length]
				if (responseHeaders.include? key)
					event.set("response_" + key, value)
				end
			elsif section == "C" || section == "I" && @store_request # Buffer request body
				reqBody += line		
			elsif section == "G" || section == "E" && @store_response # Buffer request body
				respBody += line	
			end
		end # end of for

		if @store_request == true
			event.set("_request_body",reqBody);
		end
		if @store_response == true
			event.set("_response_body",respBody);
		end

        alerts = alertsEmergency + alertsCritical + alertsAlert + alertsError + alertsWarning + alertsOther # Sorted alerts be severity desc
		if alerts.length > 0
			event.set("alerts_highest_severity",alerts[0][:severity])
		end
 
		if @split_alerts
			alertCount = 0
			alertsRemaining = []
			for alert in alerts

				# Max 6 alerts to prevent exceeding max field count
				if alertCount <= 5
					event.set("alert_" + alertCount.to_s,alert) 
				else
					alertsRemaining << alert
				end
				alertCount += 1
			end

			if alertsRemaining.length > 0
				event.set("alertsRemaining",alertsRemaining)
			end
		else
			event.set("alerts",alerts)
		end

		# Split kind by type to facilitate metrics calculation
		event.set("alert_count",alerts.length)
		event.set("alerts_emergency",alertCountEmergency)
		event.set("alerts_alert",alertCountAlert)
		event.set("alerts_critical",alertCountCritital)
		event.set("alerts_warning",alertCountWarning)
		event.set("alerts_error",alertCountError)

        if parseErrors.length > 0
			event.set("parse_errors",parseErrors)
	    end

		filter_matched(event)
	end
end